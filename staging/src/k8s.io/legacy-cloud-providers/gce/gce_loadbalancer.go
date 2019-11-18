// +build !providerless

/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package gce

import (
	"context"
	"flag"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"k8s.io/api/core/v1"
	"k8s.io/klog"

	"github.com/GoogleCloudPlatform/k8s-cloud-provider/pkg/cloud"
	cloudprovider "k8s.io/cloud-provider"
	utilnet "k8s.io/utils/net"
)

type cidrs struct {
	ipn   utilnet.IPNetSet
	isSet bool
}

var (
	l4LbSrcRngsFlag cidrs
	l7lbSrcRngsFlag cidrs
)

func init() {
	var err error
	// L3/4 health checkers have client addresses within these known CIDRs.
	l4LbSrcRngsFlag.ipn, err = utilnet.ParseIPNets([]string{"130.211.0.0/22", "35.191.0.0/16", "209.85.152.0/22", "209.85.204.0/22"}...)
	if err != nil {
		panic("Incorrect default GCE L3/4 source ranges")
	}
	// L7 health checkers have client addresses within these known CIDRs.
	l7lbSrcRngsFlag.ipn, err = utilnet.ParseIPNets([]string{"130.211.0.0/22", "35.191.0.0/16"}...)
	if err != nil {
		panic("Incorrect default GCE L7 source ranges")
	}

	flag.Var(&l4LbSrcRngsFlag, "cloud-provider-gce-lb-src-cidrs", "CIDRs opened in GCE firewall for L4 LB traffic proxy & health checks")
	flag.Var(&l7lbSrcRngsFlag, "cloud-provider-gce-l7lb-src-cidrs", "CIDRs opened in GCE firewall for L7 LB traffic proxy & health checks")
}

// String is the method to format the flag's value, part of the flag.Value interface.
func (c *cidrs) String() string {
	s := c.ipn.StringSlice()
	sort.Strings(s)
	return strings.Join(s, ",")
}

// Set supports a value of CSV or the flag repeated multiple times
func (c *cidrs) Set(value string) error {
	// On first Set(), clear the original defaults
	if !c.isSet {
		c.isSet = true
		c.ipn = make(utilnet.IPNetSet)
	} else {
		return fmt.Errorf("GCE LB CIDRs have already been set")
	}

	for _, cidr := range strings.Split(value, ",") {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return err
		}

		c.ipn.Insert(ipnet)
	}
	return nil
}

// L4LoadBalancerSrcRanges contains the ranges of ips used by the L3/L4 GCE load balancers
// for proxying client requests and performing health checks.
func L4LoadBalancerSrcRanges() []string {
	return l4LbSrcRngsFlag.ipn.StringSlice()
}

// L7LoadBalancerSrcRanges contains the ranges of ips used by the GCE load balancers L7
// for proxying client requests and performing health checks.
func L7LoadBalancerSrcRanges() []string {
	return l7lbSrcRngsFlag.ipn.StringSlice()
}

// GetLoadBalancer is an implementation of LoadBalancer.GetLoadBalancer
func (g *Cloud) GetLoadBalancer(ctx context.Context, clusterName string, svc *v1.Service) (*v1.LoadBalancerStatus, bool, error) {
	loadBalancerName := g.GetLoadBalancerName(ctx, clusterName, svc)
	fwd, err := g.GetRegionForwardingRule(loadBalancerName, g.region)
	if err == nil {
		status := &v1.LoadBalancerStatus{}
		status.Ingress = []v1.LoadBalancerIngress{{IP: fwd.IPAddress}}

		return status, true, nil
	}
	return nil, false, ignoreNotFound(err)
}

// GetLoadBalancerName is an implementation of LoadBalancer.GetLoadBalancerName.
func (g *Cloud) GetLoadBalancerName(ctx context.Context, clusterName string, svc *v1.Service) string {
	// TODO: replace DefaultLoadBalancerName to generate more meaningful loadbalancer names.
	return cloudprovider.DefaultLoadBalancerName(svc)
}

// EnsureLoadBalancer is an implementation of LoadBalancer.EnsureLoadBalancer.
func (g *Cloud) EnsureLoadBalancer(ctx context.Context, clusterName string, svc *v1.Service, nodes []*v1.Node) (*v1.LoadBalancerStatus, error) {
	loadBalancerName := g.GetLoadBalancerName(ctx, clusterName, svc)
	desiredScheme := getSvcScheme(svc)
	clusterID, err := g.ClusterID.GetID()
	if err != nil {
		return nil, err
	}

	klog.V(4).Infof("EnsureLoadBalancer(%v, %v, %v, %v, %v): ensure %v loadbalancer", clusterName, svc.Namespace, svc.Name, loadBalancerName, g.region, desiredScheme)

	existingFwdRule, err := g.GetRegionForwardingRule(loadBalancerName, g.region)
	if err != nil && !isNotFound(err) {
		return nil, err
	}

	if existingFwdRule != nil {
		existingScheme := cloud.LbScheme(strings.ToUpper(existingFwdRule.LoadBalancingScheme))

		// If the loadbalancer type changes between INTERNAL and EXTERNAL, the old load balancer should be deleted.
		if existingScheme != desiredScheme {
			klog.V(4).Infof("EnsureLoadBalancer(%v, %v, %v, %v, %v): deleting existing %v loadbalancer", clusterName, svc.Namespace, svc.Name, loadBalancerName, g.region, existingScheme)
			switch existingScheme {
			case cloud.SchemeInternal:
				err = g.ensureInternalLoadBalancerDeleted(clusterName, clusterID, svc)
			default:
				err = g.ensureExternalLoadBalancerDeleted(clusterName, clusterID, svc)
			}
			klog.V(4).Infof("EnsureLoadBalancer(%v, %v, %v, %v, %v): done deleting existing %v loadbalancer. err: %v", clusterName, svc.Namespace, svc.Name, loadBalancerName, g.region, existingScheme, err)
			if err != nil {
				return nil, err
			}

			// Assume the ensureDeleted function successfully deleted the forwarding rule.
			existingFwdRule = nil
		}
	}

	var status *v1.LoadBalancerStatus
	switch desiredScheme {
	case cloud.SchemeInternal:
		status, err = g.ensureInternalLoadBalancer(clusterName, clusterID, svc, existingFwdRule, nodes)
	default:
		status, err = g.ensureExternalLoadBalancer(clusterName, clusterID, svc, existingFwdRule, nodes)
	}
	if err != nil {
		klog.Errorf("Failed to EnsureLoadBalancer(%s, %s, %s, %s, %s), err: %v", clusterName, svc.Namespace, svc.Name, loadBalancerName, g.region, err)
		return status, err
	}
	klog.V(4).Infof("EnsureLoadBalancer(%s, %s, %s, %s, %s): done ensuring loadbalancer.", clusterName, svc.Namespace, svc.Name, loadBalancerName, g.region)
	return status, err
}

// UpdateLoadBalancer is an implementation of LoadBalancer.UpdateLoadBalancer.
func (g *Cloud) UpdateLoadBalancer(ctx context.Context, clusterName string, svc *v1.Service, nodes []*v1.Node) error {
	loadBalancerName := g.GetLoadBalancerName(ctx, clusterName, svc)
	scheme := getSvcScheme(svc)
	clusterID, err := g.ClusterID.GetID()
	if err != nil {
		return err
	}

	klog.V(4).Infof("UpdateLoadBalancer(%v, %v, %v, %v, %v): updating with %d nodes", clusterName, svc.Namespace, svc.Name, loadBalancerName, g.region, len(nodes))

	switch scheme {
	case cloud.SchemeInternal:
		err = g.updateInternalLoadBalancer(clusterName, clusterID, svc, nodes)
	default:
		err = g.updateExternalLoadBalancer(clusterName, svc, nodes)
	}
	klog.V(4).Infof("UpdateLoadBalancer(%v, %v, %v, %v, %v): done updating. err: %v", clusterName, svc.Namespace, svc.Name, loadBalancerName, g.region, err)
	return err
}

// EnsureLoadBalancerDeleted is an implementation of LoadBalancer.EnsureLoadBalancerDeleted.
func (g *Cloud) EnsureLoadBalancerDeleted(ctx context.Context, clusterName string, svc *v1.Service) error {
	loadBalancerName := g.GetLoadBalancerName(ctx, clusterName, svc)
	scheme := getSvcScheme(svc)
	clusterID, err := g.ClusterID.GetID()
	if err != nil {
		return err
	}

	klog.V(4).Infof("EnsureLoadBalancerDeleted(%v, %v, %v, %v, %v): deleting loadbalancer", clusterName, svc.Namespace, svc.Name, loadBalancerName, g.region)

	switch scheme {
	case cloud.SchemeInternal:
		err = g.ensureInternalLoadBalancerDeleted(clusterName, clusterID, svc)
	default:
		err = g.ensureExternalLoadBalancerDeleted(clusterName, clusterID, svc)
	}
	klog.V(4).Infof("EnsureLoadBalancerDeleted(%v, %v, %v, %v, %v): done deleting loadbalancer. err: %v", clusterName, svc.Namespace, svc.Name, loadBalancerName, g.region, err)
	return err
}

func getSvcScheme(svc *v1.Service) cloud.LbScheme {
	if t := GetLoadBalancerAnnotationType(svc); t == LBTypeInternal {
		return cloud.SchemeInternal
	}
	return cloud.SchemeExternal
}

// getPortsAndProtocol returns the service ports, port ranges and protocol.
func getPortsAndProtocol(svcPorts []v1.ServicePort) (ports []string, portRanges []string, protocol v1.Protocol) {
	if len(svcPorts) == 0 {
		return []string{}, []string{}, v1.ProtocolUDP
	}

	// GCP doesn't support multiple protocols for a single load balancer
	protocol = svcPorts[0].Protocol
	portInts := []int{}
	for _, p := range svcPorts {
		ports = append(ports, strconv.Itoa(int(p.Port)))
		portInts = append(portInts, int(p.Port))
	}

	return ports, getPortRanges(portInts), protocol
}

// getPortRanges returns a list of port ranges, given a list of ports.
func getPortRanges(ports []int) (ranges []string) {
	if len(ports) < 1 {
		return ranges
	}
	sort.Ints(ports)

	start := ports[0]
	prev := ports[0]
	for ix, current := range ports {
		switch {
		case current == prev:
			// Loop over duplicates, except if the end of list is reached.
			if ix == len(ports)-1 {
				if start == current {
					ranges = append(ranges, fmt.Sprintf("%d", current))
				} else {
					ranges = append(ranges, fmt.Sprintf("%d-%d", start, current))
				}
			}
		case current == prev+1:
			// continue the streak, create the range if this is the last element in the list.
			if ix == len(ports)-1 {
				ranges = append(ranges, fmt.Sprintf("%d-%d", start, current))
			}
		default:
			// current is not prev + 1, streak is broken. Construct the range and handle last element case.
			if start == prev {
				ranges = append(ranges, fmt.Sprintf("%d", prev))
			} else {
				ranges = append(ranges, fmt.Sprintf("%d-%d", start, prev))
			}
			if ix == len(ports)-1 {
				ranges = append(ranges, fmt.Sprintf("%d", current))
			}
			// reset start element
			start = current
		}
		prev = current
	}
	return ranges
}
