// This is a generated file. Do not edit directly.

module k8s.io/legacy-cloud-providers

go 1.12

require (
	cloud.google.com/go v0.38.0
	github.com/Azure/azure-sdk-for-go v21.4.0+incompatible
	github.com/Azure/go-autorest v11.1.2+incompatible
	github.com/GoogleCloudPlatform/k8s-cloud-provider v0.0.0-20190803003326-2de84d8b30ca
	github.com/aws/aws-sdk-go v1.16.26
	github.com/dnaeon/go-vcr v1.0.1 // indirect
	github.com/marstr/guid v0.0.0-20170427235115-8bdf7d1a087c // indirect
	github.com/prometheus/client_golang v0.9.2
	github.com/rubiojr/go-vhd v0.0.0-20160810183302-0bfd3b39853c
	github.com/satori/go.uuid v1.2.0 // indirect
	github.com/stretchr/testify v1.3.0
	github.com/vmware/govmomi v0.20.1
	golang.org/x/crypto v0.0.0-20190611184440-5c40567a22f8
	golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45
	google.golang.org/api v0.6.1-0.20190607001116-5213b8090861
	gopkg.in/gcfg.v1 v1.2.0
	gopkg.in/warnings.v0 v0.1.1 // indirect
	k8s.io/api v0.0.0
	k8s.io/apimachinery v0.0.0
	k8s.io/apiserver v0.0.0
	k8s.io/client-go v0.0.0
	k8s.io/cloud-provider v0.0.0
	k8s.io/component-base v0.0.0
	k8s.io/csi-translation-lib v0.0.0
	k8s.io/klog v0.4.0
	k8s.io/utils v0.0.0-20190801114015-581e00157fb1
	sigs.k8s.io/yaml v1.1.0
)

replace (
	cloud.google.com/go => cloud.google.com/go v0.34.0
	github.com/golang/protobuf => github.com/golang/protobuf v1.2.0
	github.com/hashicorp/golang-lru => github.com/hashicorp/golang-lru v0.5.0
	golang.org/x/crypto => golang.org/x/crypto v0.0.0-20181025213731-e84da0312774
	golang.org/x/lint => golang.org/x/lint v0.0.0-20181217174547-8f45f776aaf1
	golang.org/x/oauth2 => golang.org/x/oauth2 v0.0.0-20190402181905-9f3314589c9a
	golang.org/x/sync => golang.org/x/sync v0.0.0-20181108010431-42b317875d0f
	golang.org/x/sys => golang.org/x/sys v0.0.0-20190209173611-3b5209105503
	golang.org/x/text => golang.org/x/text v0.3.1-0.20181227161524-e6919f6577db
	golang.org/x/tools => golang.org/x/tools v0.0.0-20190313210603-aa82965741a9
	google.golang.org/genproto => google.golang.org/genproto v0.0.0-20170731182057-09f6ed296fc6
	google.golang.org/grpc => google.golang.org/grpc v1.13.0
	k8s.io/api => ../api
	k8s.io/apimachinery => ../apimachinery
	k8s.io/apiserver => ../apiserver
	k8s.io/client-go => ../client-go
	k8s.io/cloud-provider => ../cloud-provider
	k8s.io/component-base => ../component-base
	k8s.io/csi-translation-lib => ../csi-translation-lib
	k8s.io/legacy-cloud-providers => ../legacy-cloud-providers
)
