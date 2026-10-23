package device_test

import (
	"fmt"

	device "github.com/faustbrian/go-oauth-server/device"
)

func ExampleNewService_disabled() {
	service, err := device.NewService(nil, device.Config{}, nil)
	if err != nil {
		return
	}
	fmt.Println(service.Enabled(), service.Metadata().GrantType == "")
	// Output: false true
}
