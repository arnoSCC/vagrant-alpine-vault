# -*- mode: ruby -*-
# vi: set ft=ruby :

VM_MEMORY=8172
VM_CORES=4

Vagrant.configure("2") do |config|

  config.vm.box = "generic/alpine38"

  config.vm.provider :vmware_desktop do |v, override|
    v.vmx['memsize'] = VM_MEMORY
    v.vmx['numvcpus'] = VM_CORES
  end

  config.vm.provider :virtualbox do |v, override|
    v.memory = VM_MEMORY
    v.cpus = VM_CORES
  end

  config.vm.provision "shell", inline: <<-SHELL
echo "vagrant.$(ip a show dev eth0 | grep -m1 inet | awk '{print $2}' | cut -d'/' -f1).xip.io" > /etc/hostname
hostname -F /etc/hostname
apk add unzip shadow openssl libcap jq
echo "Downloading Consul..."
curl -sSLO https://releases.hashicorp.com/consul/1.4.4/consul_1.4.4_linux_amd64.zip
unzip consul_1.4.4_linux_amd64.zip && rm -f consul_1.4.4_linux_amd64.zip
mv consul /usr/local/bin
chown root:root /usr/local/bin/consul
useradd --system --home /etc/consul.d --shell /bin/false consul
mkdir --parents /opt/consul
openssl req -x509 -nodes -newkey rsa:4096 -keyout /opt/consul/key.pem -out /opt/consul/cert.pem -days 365 -subj "/CN=consul.$(ip a show dev eth0 | grep -m1 inet | awk '{print $2}' | cut -d'/' -f1).xip.io" 2>/dev/null
chown --recursive consul:consul /opt/consul
mkdir --parents /etc/consul.d
cat<<EOF>/etc/consul.d/consul.hcl
datacenter = "dc1",
data_dir = "/opt/consul"
encrypt = "$(openssl rand -base64 24)"
EOF
cat<<EOF>/etc/consul.d/server.hcl
server = true
ui = true
disable_update_check = true
bootstrap_expect = 1
EOF
cat<<EOF>/etc/consul.d/acl.hcl
{
  "acl": {
    "enabled": true,
    "default_policy": "deny",
    "down_policy": "extend-cache"
  }
}
EOF
cat<<EOF>/etc/consul.d/addr.hcl
{
  "addresses": {
    "http": "127.0.0.1",
    "https": "0.0.0.0"
  },
  "ports": {
    "http": 8500,
    "https": 8501
  },
  "key_file": "/opt/consul/key.pem",
  "cert_file": "/opt/consul/cert.pem",
  "ca_file": "/opt/consul/cert.pem"
}
EOF
chmod 640 /etc/consul.d/*
chown --recursive consul:consul /etc/consul.d
cat<<EOF>/etc/init.d/consul
#!/sbin/openrc-run

name="Consul"
command="/usr/local/bin/consul"
command_args="agent -config-dir=/etc/consul.d/"
command_background="yes"
command_user="consul"
pidfile="/run/consul/consul.pid"
start_stop_daemon_args="--make-pidfile -1 /var/log/consul/stdout.log -2 /var/log/consul/stderr.log"
extra_started_commands="reload"

depend() {
        need net
}

start_pre() {
        checkpath --directory --owner consul:consul --mode 0775 /run/consul /var/log/consul
}

reload() {
        if [ -f /opt/consul/bootstrap ]; then
            /usr/local/bin/consul reload --token \\$(cat /opt/consul/bootstrap)
        else
            /usr/local/bin/consul reload
        fi
}
EOF
chmod +x /etc/init.d/consul
rc-update add consul default
service consul start
echo "Sleeping for 30s for Consul to start and elect leader"
sleep 30
echo $(consul acl bootstrap | grep SecretID | awk '{print $2}') > /opt/consul/bootstrap
chown consul:consul /opt/consul/bootstrap
chmod 640 /opt/consul/bootstrap
cat<<EOF>/tmp/agent.hcl
node_prefix "" {policy="write"}
service_prefix "" {policy = "read"}
EOF
consul acl policy create -name "agent-token" -rules @/tmp/agent.hcl --token $(cat /opt/consul/bootstrap) 1>/dev/null 2>&1
rm -f /tmp/agent.hcl
AGENT_TOKEN=$(consul acl token create -description "Agent Token" -policy-name "agent-token" --token $(cat /opt/consul/bootstrap) | grep SecretID | awk '{print $2}')
cat<<EOF>/etc/consul.d/acl.hcl
{
  "primary_datacenter": "dc1",
  "acl": {
    "enabled": true,
    "default_policy": "deny",
    "down_policy": "extend-cache",
    "tokens": {
      "agent": "$AGENT_TOKEN"
    }
  }
}
EOF
service consul reload
echo "Downloading Vault..."
curl -sSLO https://releases.hashicorp.com/vault/1.1.0/vault_1.1.0_linux_amd64.zip
unzip vault_1.1.0_linux_amd64.zip && rm -f consul_1.4.4_linux_amd64.zip
mv vault /usr/local/bin
chown root:root /usr/local/bin/vault
setcap cap_ipc_lock=+ep /usr/local/bin/vault
useradd --system --home /opt/vault --shell /bin/false vault
mkdir --parents /opt/vault
chown --recursive vault:vault /opt/vault
mkdir --parents /etc/vault.d
openssl req -x509 -nodes -newkey rsa:4096 -keyout /etc/vault.d/key.pem -out /etc/vault.d/cert.pem -days 365 -subj "/CN=vault.$(ip a show dev eth0 | grep -m1 inet | awk '{print $2}' | cut -d'/' -f1).xip.io" 2>/dev/null
cat<<EOF>/tmp/vault.hcl
node_prefix "" {policy="write"}
service "vault" {policy="write"}
agent_prefix "" {policy="write"}
key_prefix "vault/" {policy="write"}
session_prefix "" {policy="write"}
EOF
consul acl policy create -name "vault-token" -rules @/tmp/vault.hcl --token $(cat /opt/consul/bootstrap) 1>/dev/null 2>&1
rm -f /tmp/vault.hcl
VAULT_TOKEN=$(consul acl token create -description "Vault Token" -policy-name "vault-token" --token $(cat /opt/consul/bootstrap) | grep SecretID | awk '{print $2}')
cat<<EOF>/etc/vault.d/vault.hcl
listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_cert_file = "/etc/vault.d/cert.pem"
  tls_key_file  = "/etc/vault.d/key.pem"
}
storage "consul" {
  token = "$VAULT_TOKEN"
}
ui = true
EOF
chown --recursive vault:vault /etc/vault.d
chmod 640 /etc/vault.d/*
cat<<EOF>/etc/init.d/vault
#!/sbin/openrc-run

name="Vault"
command="/usr/local/bin/vault"
command_args="server -config=/etc/vault.d/vault.hcl"
command_background="yes"
command_user="vault"
pidfile="/run/vault/vault.pid"
start_stop_daemon_args="--make-pidfile -1 /var/log/vault/stdout.log -2 /var/log/vault/stderr.log"

depend() {
        need net
}

start_pre() {
        checkpath --directory --owner vault:vault --mode 0775 /run/vault /var/log/vault
}

EOF
chmod +x /etc/init.d/vault
rc-update add vault default
service vault start
echo "Sleeping for 10s for Vault to start"
sleep 10
vault operator init -tls-skip-verify -key-shares=1 -key-threshold=1 > /opt/vault/bootstrap
vault operator unseal -tls-skip-verify $(cat /opt/vault/bootstrap | grep Unseal | awk '{print $4}') 1>/dev/null 2>&1
chown vault:vault /opt/vault/bootstrap
chmod 640 /opt/vault/bootstrap
echo "export VAULT_SKIP_VERIFY=true" >> /etc/profile
echo "\nConsul available at https://consul.$(ip a show dev eth0 | grep -m1 inet | awk '{print $2}' | cut -d'/' -f1).xip.io:8501/ui with bootstrap token $(cat /opt/consul/bootstrap)"
echo "Vault available at https://vault.$(ip a show dev eth0 | grep -m1 inet | awk '{print $2}' | cut -d'/' -f1).xip.io:8200/ui with root token $(cat /opt/vault/bootstrap | grep Root | awk '{print $4}')"
  SHELL

end
