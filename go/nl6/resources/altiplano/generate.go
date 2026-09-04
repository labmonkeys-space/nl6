//go:build generate
// +build generate

package altiplano

//go:generate go run github.com/openconfig/ygot/generator -path=yang -output_file=device_models.go -package_name=altiplano -generate_fakeroot -fakeroot_name=device -compress_paths=false yang/openconfig-interfaces.yang yang/bbf-tr-413.yang yang/bbf-tr-384.yang
