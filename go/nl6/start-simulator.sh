sudo ls -lt
# -snmpv3-auth/-snmpv3-priv are omitted deliberately: authentication is not
# implemented and privacy needs authPriv, so only noAuthNoPriv is reachable
# (nl6#624). Poll with: snmpget -v3 -l noAuthNoPriv -u simadmin -e 800000090300AABBCCDD
sudo ./nl6 -auto-start-ip 10.10.10.1 -auto-count 1 -snmpv3-engine-id 800000090300AABBCCDD &
