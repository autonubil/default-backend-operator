package operator

/*
Copyright [2019] [autonubil System GmbH]

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

import (
	"time"

	extensionsv1beta "k8s.io/api/extensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/apimachinery/pkg/runtime"

	"k8s.io/client-go/kubernetes"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/watch"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	"github.com/golang/glog"

	"github.com/autonubil/default-backend-operator/pkg/types"
	"github.com/autonubil/default-backend-operator/pkg/utils"
)

// Implements an ingressConfig's controller loop in a particular namespace.
// The controller makes use of an Informer resource to locally cache resources
// managed, and handle events on the resources.
type ingressConfigController struct {
	// Baseline kubeconfig to use when communicating with the API.
	kubecfg *rest.Config

	// Clientset that has a REST client for each k8s API group.
	clientSet kubernetes.Interface

	// Informer for all resources being watched by the operator.
	informer *ingressConfigControllerInformer

	options *types.BackendOperatorOptions
}

// Implements an Informer for the resources being operated on: ingresss &
// ingressConfigs.
type ingressConfigControllerInformer struct {
	// Store & controller for ingress resources
	ingressStore      cache.Store
	ingressController cache.Controller
}

// Create a new Controller for the ingressConfig operator
func NewingressConfigController(options *types.BackendOperatorOptions) (
	*ingressConfigController, error) {

	// Create the client config for use in creating the k8s API client
	// Use kubeconfig if given, otherwise use in-clust
	kubecfg, err := utils.BuildKubeConfig(options.KubeConfig)
	if err != nil {
		return nil, err
	}

	// Create a new k8s API client from the kubeconfig
	clientSet, err := kubernetes.NewForConfig(kubecfg)
	if err != nil {
		return nil, err
	}

	// Create a new k8s REST API client for ingressConfigs
	// Create new ingressConfigController
	npc := &ingressConfigController{
		kubecfg:   kubecfg,
		clientSet: clientSet,
		options:   options,
	}

	// Create a new Informer for the ingressConfigController
	npc.informer = npc.newIngressConfigControllerInformer()

	return npc, nil
}

// Start the ingressConfigController until stopped.
func (npc *ingressConfigController) Start(stop <-chan struct{}) {
	// Don't let panics crash the process
	defer utilruntime.HandleCrash()

	npc.start(stop)

	// Block until stopped
	<-stop
}

// Start the controllers with the stop chan as required by Informers.
func (npc *ingressConfigController) start(stop <-chan struct{}) {
	namespace := npc.options.Namespace
	if namespace == "" {
		namespace = "<any>"
	}

	watched := ""
	if npc.options.Label != "" {
		watched = watched + npc.options.Label
	}
	if npc.options.Label != "" {
		if watched != "" {
			watched = watched + " and "
		}
		watched = watched + npc.options.Label
	}
	glog.V(2).Infof("Start watching Namespace: %s for %s", namespace, watched)

	// Run controller for ingress Informer and handle events via callbacks
	go npc.informer.ingressController.Run(stop)

}

// Informers are a combination of a local cache store to buffer the state of a
// given resource locally, and a controller to handle events through callbacks.
//
// Informers sync the APIServer's state of a resource with the local cache
// store.

// Creates a new Informer for the ingressConfigController.
// An ingressConfigController uses a set of Informers to watch and operate on
// ingresss and ingressConfig resources in its control loop.
func (npc *ingressConfigController) newIngressConfigControllerInformer() *ingressConfigControllerInformer {
	ingressStore, ingressController := npc.newIngressInformer()

	return &ingressConfigControllerInformer{
		ingressStore:      ingressStore,
		ingressController: ingressController,
	}
}

// Create a new Informer on the ingress resources in the cluster to track them.
func (npc *ingressConfigController) newIngressInformer() (cache.Store, cache.Controller) {
	var timeout int64
	timeout = 30
	filter := ""
	if npc.options.Label != "" {
		filter = npc.options.Label
	}

	return cache.NewInformer(
		&cache.ListWatch{
			ListFunc: func(alo metav1.ListOptions) (runtime.Object, error) {
				// Retrieve a ingressList from the the API
				lo := metav1.ListOptions{IncludeUninitialized: false, TimeoutSeconds: &timeout}
				if filter != "" {
					lo.LabelSelector = filter
				}
				return npc.clientSet.ExtensionsV1beta1().Ingresses(npc.options.Namespace).List(lo)
			},
			WatchFunc: func(alo metav1.ListOptions) (watch.Interface, error) {
				// Watch the ingresss in the API
				lo := metav1.ListOptions{IncludeUninitialized: false}
				if filter != "" {
					lo.LabelSelector = filter
				}
				return npc.clientSet.ExtensionsV1beta1().Ingresses(npc.options.Namespace).Watch(lo)
			},
		},
		// The resource that the informer returns
		&extensionsv1beta.Ingress{},
		// The sync interval of the informer
		0*time.Second,
		// Callback functions for add, delete & update events
		cache.ResourceEventHandlerFuncs{
			// AddFunc: func(o interface{}) {}
			UpdateFunc: npc.handleIngressUpdate,
			DeleteFunc: npc.handleIngressDelete,
		},
	)
}

func (npc *ingressConfigController) isWatchedLabel(ingress *extensionsv1beta.Ingress) bool {
	if (npc.options.Label == "") || utils.IsIngressLabeled(ingress, npc.options.Label) {
		return true
	}
	return false
}

func (npc *ingressConfigController) handleIngressDelete(obj interface{}) {
	ingress := obj.(*extensionsv1beta.Ingress)
	glog.V(11).Infof("Received delete for ingress: %s/%s", ingress.Namespace, ingress.Name)
	if npc.isWatchedLabel(ingress) {
		delete(npc.options.Data.Services, string(ingress.UID))
	} else {
		glog.V(12).Infof("Skipping non ingress labeled ingress: %s/%s", ingress.Namespace, ingress.Name)
	}
}

// Callback for updates to a ingress Informer
func (npc *ingressConfigController) handleIngressUpdate(oldObj, newObj interface{}) {
	ingress := newObj.(*extensionsv1beta.Ingress)
	// oldingress := oldObj.(*extensionsv1beta.Ingress)
	glog.V(11).Infof("Received update for ingress: %s/%s", ingress.Namespace, ingress.Name)
	if npc.isWatchedLabel(ingress) {
		svc := npc.options.NewService(ingress)
		npc.options.Data.Services[string(ingress.UID)] = svc
	} else {
		glog.V(12).Infof("Skipping non ingress labeled ingress: %s/%s", ingress.Namespace, ingress.Name)
	}

}
