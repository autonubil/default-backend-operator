package backend

import (
	"encoding/json"
	"fmt"
	"net/http"

	raven "github.com/getsentry/raven-go"

	"github.com/golang/glog"

	"github.com/autonubil/default-backend-operator/pkg/operator"
)

// A webhook handler with a "ServeHTTP" method:
type BackendHandler struct {
	Options *operator.BackendOperatorOptions
}

// Handle webhook requests:
func (backendHandler *BackendHandler) ServeHTTP(responseWriter http.ResponseWriter, request *http.Request) {

	/*
		// Read the request body:
		payload, err := ioutil.ReadAll(request.Body)
		defer request.Body.Close()
		if err != nil {
			raven.CaptureError(err, map[string]string{"payload": "payload"})
			glog.Errorf("Failed to read the request body: %s", err)
			http.Error(responseWriter, "Failed to read the request body", http.StatusBadRequest)
			return
		}
	*/

	data, err := json.Marshal(backendHandler.Options.Data)
	if err != nil {
		raven.CaptureError(err, map[string]string{})
		glog.Errorf("Failed to marshall services: %s", err)
		http.Error(responseWriter, "Failed to marshall services", http.StatusBadRequest)
		return
	}

	responseWriter.Header().Set("Content-Type", "application/json; charset=utf-8")
	responseWriter.Header().Set("X-Content-Type-Options", "nosniff")
	responseWriter.WriteHeader(200)

	fmt.Fprintln(responseWriter, string(data))

	/*
		// Validate the payload:
		err, alerts := validatePayload(payload)
		if err != nil {
			raven.CaptureError(err, map[string]string{"payload": "payload"})
			http.Error(responseWriter, "Failed to unmarshal the request-body into an alert", http.StatusBadRequest)
			return
		}

		// Send the alerts to the snmp-trapper:
		for alertIndex, alert := range alerts {
			log.WithFields(logrus.Fields{"index": alertIndex, "status": alert.Status, "labels": alert.Labels}).Debug("Forwarding an alert to the SNMP trapper")

			// Enrich the request with the remote-address:
			alert.Address = request.RemoteAddr
			// Put the alert onto the alerts-channel:
			BackendHandler.AlertsChannel <- alert
		}
	*/
}
