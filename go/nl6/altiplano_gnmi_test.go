package main

import (
	"context"
	"net"
	"testing"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
)

func TestAltiplanoGNMISubscribeCounters(t *testing.T) {
	dev := &DeviceSimulator{
		IP: net.ParseIP("10.0.0.1"),
		resourceFile: "altiplano.json",
	}
	dev.initAltiplanoData()

	// Create request
	req := &gnmipb.SubscribeRequest{
		Request: &gnmipb.SubscribeRequest_Subscribe{
			Subscribe: &gnmipb.SubscriptionList{
				Subscription: []*gnmipb.Subscription{
					{
						Path: &gnmipb.Path{
							Elem: []*gnmipb.PathElem{
								{Name: "interfaces"},
								{Name: "interface", Key: map[string]string{"name": "eth1"}},
								{Name: "state"},
								{Name: "counters"},
							},
						},
						Mode: gnmipb.SubscriptionMode_SAMPLE,
					},
				},
				Mode: gnmipb.SubscriptionList_STREAM,
				Encoding: gnmipb.Encoding_JSON_IETF,
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	
	stream := newFakeSubscribeStream(ctx)
	stream.recvQueue <- req

	resolver := newPathResolver(dev)
	
	// This will block until context deadline, so we run it in a goroutine
	var updatesSent uint64
	var dialoutUpdatesSent uint64
	go runStreamSubscribe(stream, resolver, req.GetSubscribe().GetSubscription(), req.GetSubscribe().GetEncoding(), &updatesSent, &dialoutUpdatesSent)
	
	// Wait for a response (the initial snapshot)
	select {
	case resp := <-stream.sent:
		// Check that it's an update containing the counters
		if update := resp.GetUpdate(); update != nil {
			if len(update.Update) == 0 {
				t.Fatalf("Expected updates, got none")
			}
			found := false
			for _, u := range update.Update {
				if len(u.Path.Elem) > 0 && u.Path.Elem[0].Name == "interfaces" {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected interfaces path in response, got %v", update.Update)
			}
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("Timed out waiting for gNMI subscribe response")
	}
}
