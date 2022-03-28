//
// Copyright 2021 IBM Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"

	v1beta1 "github.com/argoproj-labs/argocd-interlace/pkg/apis/applicationprovenance/v1beta1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeApplicationProvenances implements ApplicationProvenanceInterface
type FakeApplicationProvenances struct {
	Fake *FakeInterlaceV1beta1
	ns   string
}

var applicationprovenancesResource = schema.GroupVersionResource{Group: "interlace.argocd.dev", Version: "v1beta1", Resource: "applicationprovenances"}

var applicationprovenancesKind = schema.GroupVersionKind{Group: "interlace.argocd.dev", Version: "v1beta1", Kind: "ApplicationProvenance"}

// Get takes name of the applicationProvenance, and returns the corresponding applicationProvenance object, and an error if there is any.
func (c *FakeApplicationProvenances) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1beta1.ApplicationProvenance, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(applicationprovenancesResource, c.ns, name), &v1beta1.ApplicationProvenance{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1beta1.ApplicationProvenance), err
}

// List takes label and field selectors, and returns the list of ApplicationProvenances that match those selectors.
func (c *FakeApplicationProvenances) List(ctx context.Context, opts v1.ListOptions) (result *v1beta1.ApplicationProvenanceList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(applicationprovenancesResource, applicationprovenancesKind, c.ns, opts), &v1beta1.ApplicationProvenanceList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1beta1.ApplicationProvenanceList{ListMeta: obj.(*v1beta1.ApplicationProvenanceList).ListMeta}
	for _, item := range obj.(*v1beta1.ApplicationProvenanceList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested applicationProvenances.
func (c *FakeApplicationProvenances) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(applicationprovenancesResource, c.ns, opts))

}

// Create takes the representation of a applicationProvenance and creates it.  Returns the server's representation of the applicationProvenance, and an error, if there is any.
func (c *FakeApplicationProvenances) Create(ctx context.Context, applicationProvenance *v1beta1.ApplicationProvenance, opts v1.CreateOptions) (result *v1beta1.ApplicationProvenance, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(applicationprovenancesResource, c.ns, applicationProvenance), &v1beta1.ApplicationProvenance{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1beta1.ApplicationProvenance), err
}

// Update takes the representation of a applicationProvenance and updates it. Returns the server's representation of the applicationProvenance, and an error, if there is any.
func (c *FakeApplicationProvenances) Update(ctx context.Context, applicationProvenance *v1beta1.ApplicationProvenance, opts v1.UpdateOptions) (result *v1beta1.ApplicationProvenance, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(applicationprovenancesResource, c.ns, applicationProvenance), &v1beta1.ApplicationProvenance{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1beta1.ApplicationProvenance), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeApplicationProvenances) UpdateStatus(ctx context.Context, applicationProvenance *v1beta1.ApplicationProvenance, opts v1.UpdateOptions) (*v1beta1.ApplicationProvenance, error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceAction(applicationprovenancesResource, "status", c.ns, applicationProvenance), &v1beta1.ApplicationProvenance{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1beta1.ApplicationProvenance), err
}

// Delete takes name of the applicationProvenance and deletes it. Returns an error if one occurs.
func (c *FakeApplicationProvenances) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteActionWithOptions(applicationprovenancesResource, c.ns, name, opts), &v1beta1.ApplicationProvenance{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeApplicationProvenances) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(applicationprovenancesResource, c.ns, listOpts)

	_, err := c.Fake.Invokes(action, &v1beta1.ApplicationProvenanceList{})
	return err
}

// Patch applies the patch and returns the patched applicationProvenance.
func (c *FakeApplicationProvenances) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1beta1.ApplicationProvenance, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(applicationprovenancesResource, c.ns, name, pt, data, subresources...), &v1beta1.ApplicationProvenance{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1beta1.ApplicationProvenance), err
}
