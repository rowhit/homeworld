import atexit
import hashlib
import os
import subprocess
import tempfile
import threading
import time

import access
import command
import configuration
import infra
import seq


def get_bridge(ip):
    return "spirebr%s" % hex(ip.to_integer())[2:].upper()


def get_node_tap(node):
    # maximum length: 15 characters
    return "spirtap%s" % hex(node.ip.to_integer())[2:].upper()


def determine_topology():
    config = configuration.get_config()
    gateway_ip = config.cidr_nodes.gateway()
    gateway = "%s/%d" % (gateway_ip, config.cidr_nodes.bits)
    taps = []
    hosts = {}
    for node in config.nodes:
        if node.ip not in config.cidr_nodes:
            command.fail("invalid topology: address %s is not in CIDR %s" % (node.ip, config.cidr_nodes))
        taps.append(get_node_tap(node))
        hosts["%s.%s" % (node.hostname, config.external_domain)] = node.ip
    return gateway, taps, get_bridge(gateway_ip), hosts


def sudo(*command):
    subprocess.check_call(["sudo"] + list(command))


def sudo_ok(*command):
    return subprocess.call(["sudo"] + list(command)) == 0


def sysctl_set(key, value):
    sudo("sysctl", "-w", "--", "%s=%s" % (key, value))


def bridge_up(bridge_name, address):
    sudo("brctl", "addbr", bridge_name)
    sudo("ip", "link", "set", bridge_name, "up")
    sudo("ip", "addr", "add", address, "dev", bridge_name)


def bridge_down(bridge_name, address):
    ok = sudo_ok("ip", "addr", "del", address, "dev", bridge_name)
    ok &= sudo_ok("ip", "link", "set", bridge_name, "down")
    ok &= sudo_ok("brctl", "delbr", bridge_name)
    return ok


def tap_up(bridge_name, tap):
    sudo("ip", "tuntap", "add", "user", os.getenv("USER"), "mode", "tap", tap)
    sudo("ip", "link", "set", tap, "up", "promisc", "on")
    sudo("brctl", "addif", bridge_name, tap)


def tap_down(bridge_name, tap):
    ok = sudo_ok("brctl", "delif", bridge_name, tap)
    ok &= sudo_ok("ip", "link", "set", tap, "down")
    ok &= sudo_ok("ip", "tuntap", "del", "mode", "tap", tap)
    return ok


def does_link_exist(link):
    return subprocess.check_call(["ip", "link", "show", "dev", link],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0


def get_upstream_link():
    lines = subprocess.check_output(["ip", "-o", "-d", "route"]).decode().split("\n")
    defaults = [line for line in lines if line.startswith("unicast default via")]
    if len(defaults) != 1:
        command.fail("cannot determine upstream link from ip route output")
    link = defaults[0].split(" dev ")[1].split(" ")[0]
    if not does_link_exist(link):
        command.fail("failed to correctly determine upstream link: '%s' does not exist" % link)
    return link


def routing_up(bridge_name, upstream_link):
    sudo("iptables", "-I", "INPUT", "1", "-i", bridge_name, "-j", "ACCEPT")
    sudo("iptables", "-I", "FORWARD", "1", "-i", bridge_name, "-o", upstream_link, "-j", "ACCEPT")
    sudo("iptables", "-I", "FORWARD", "1", "-i", upstream_link, "-o", bridge_name, "-j", "ACCEPT")
    sudo("iptables", "-t", "nat", "-I", "POSTROUTING", "1", "-o", upstream_link, "-j", "MASQUERADE")


def routing_down(bridge_name, upstream_link):
    ok = sudo_ok("iptables", "-t", "nat", "-D", "POSTROUTING", "-o", upstream_link, "-j", "MASQUERADE")
    ok &= sudo_ok("iptables", "-D", "FORWARD", "-i", upstream_link, "-o", bridge_name, "-j", "ACCEPT")
    ok &= sudo_ok("iptables", "-D", "FORWARD", "-i", bridge_name, "-o", upstream_link, "-j", "ACCEPT")
    ok &= sudo_ok("iptables", "-D", "INPUT", "-i", bridge_name, "-j", "ACCEPT")
    return ok


def sudo_update_file_by_filter(filename, discard_predicate):
    with tempfile.NamedTemporaryFile(mode="w") as fw:
        with open(filename, "r") as fr:
            for line in fr:
                line = line.rstrip("\n")
                if not discard_predicate(line):
                    fw.write(line + "\n")
        fw.flush()
        sudo("cp", "--", fw.name, filename)


def sudo_append_to_file(filename, lines):
    subprocess.run(["sudo", "tee", "-a", "--", filename], stdout=subprocess.DEVNULL, check=True,
                          input="".join(("%s\n" % line) for line in lines).encode())


def hosts_up(hosts):
    assert not any("\t" in host for host in hosts.keys()) and not any("\t" in str(ip) for ip in hosts.values())
    sudo_append_to_file("/etc/hosts", ["%s\t%s" % (ip, hostname) for hostname, ip in hosts.items()])


def hosts_down(hosts):
    def is_our_host(line):
        if line.count("\t") != 1:
            return False
        ip, hostname = line.split("\t")
        return hostname in hosts and str(hosts[hostname]) == ip
    sudo_update_file_by_filter("/etc/hosts", discard_predicate=is_our_host)


def net_up():
    gateway_ip, taps, bridge_name, hosts = determine_topology()
    upstream_link = get_upstream_link()

    sysctl_set("net.ipv4.ip_forward", 1)

    try:
        bridge_up(bridge_name, gateway_ip)
        for tap in taps:
            tap_up(bridge_name, tap)

        routing_up(bridge_name, upstream_link)

        hosts_up(hosts)
    except Exception as e:
        print("woops, tearing down...")
        if not net_down():
            print("could not tear down")
        raise e


def net_down(fail=False):
    gateway_ip, taps, bridge_name, hosts = determine_topology()
    upstream_link = get_upstream_link()

    hosts_down(hosts)

    ok = routing_down(bridge_name, upstream_link)

    for tap in taps:
        ok &= tap_down(bridge_name, tap)

    ok &= bridge_down(bridge_name, gateway_ip)

    if not ok and fail:
        command.fail("tearing down network failed (maybe it was already torn down?)")
    return ok


def call_on_existence(path, callback):
    def wait_for_existence():
        # TODO: don't busywait
        while not os.path.exists(path):
            time.sleep(0.2)
        callback()
    threading.Thread(target=wait_for_existence, daemon=True).start()


# TODO: refactor
def call_transactive(args, text, delay, output_callback, output_to, kill_path):
    assert not (output_callback and output_to)
    if output_to:
        stdout_target = open(output_to, "wb")
    elif output_callback:
        stdout_target = subprocess.PIPE
    else:
        stdout_target = None
    if text:
        stdin_target = subprocess.PIPE
    elif kill_path is not None:
        stdin_target = subprocess.DEVNULL
    else:
        stdin_target = None
    keep_output_alive = False
    p = subprocess.Popen(args, stdin=stdin_target, stdout=stdout_target)
    try:
        atexit.register(p.kill)
        if kill_path is not None:
            def check_path():
                p.wait()
                if os.path.exists(kill_path):
                    os.remove(kill_path)
                if output_to:
                    if not keep_output_alive:
                        stdout_target.close()
                elif p.stdout:
                    p.stdout.close()
                if p.stdin:
                    p.stdin.close()
            threading.Thread(target=check_path, daemon=True).start()
            call_on_existence(kill_path, p.terminate)
        if text is not None:
            time.sleep(delay)
            p.stdin.write(text.encode() + b"\n")
            p.stdin.flush()
        if output_callback is not None:
            while True:
                line = p.stdout.readline()
                if not line: break
                if output_callback(line): break
            # TODO: what if the buffer fills up?
        if kill_path is None:
            return p.wait()
        keep_output_alive = True
    finally:
        if output_to:
            if not keep_output_alive:
                stdout_target.close()
        elif p.stdout:
            p.stdout.close()
        if p.stdin:
            p.stdin.close()


def qemu_raw(hd, cd=None, cpus=12, mem=2500, netif=None, input=None, input_delay=None, output_callback=None, output_to=None, kill_path=None):
    # TODO: don't blindly load kvm-intel; check type of system first
    sudo("modprobe", "kvm", "kvm-intel")

    args = ["qemu-system-x86_64"]
    args += ["-nographic", "-serial", "mon:stdio"]
    args += ["-machine", "accel=kvm", "-cpu", "host"]
    args += ["-hda", hd]
    if cd is None:
        args += ["-boot", "c"]
    else:
        args += ["-cdrom", cd]
        args += ["-boot", "d"]
    args += ["-no-reboot"]
    args += ["-smp", "%d" % int(cpus), "-m", "%d" % int(mem)]
    if netif is None:
        args += ["-net", "none"]
    else:
        digest = hashlib.sha256(netif.encode()).hexdigest()[-6:]
        macaddr = "52:54:00:%s:%s:%s" % (digest[0:2], digest[2:4], digest[4:6])
        args += ["-net", "nic,macaddr=%s" % macaddr, "-net", "tap,ifname=%s,script=no,downscript=no" % netif]
    rc = call_transactive(args, input, input_delay, output_callback, output_to, kill_path)
    if rc:
        command.fail("qemu virtual machine failed")


def get_disk_path(node):
    return os.path.join(configuration.get_project(), "virt-local", "disk-%s.qcow2" % node.hostname)


def qemu_install(node_name, iso_path, bootstrap_token, disk_gb=25, visible="show"):
    assert disk_gb > 0
    if bootstrap_token == "auto-admit":
        bootstrap_token = infra.admit(node_name)
    assert not any(c.isspace() for c in bootstrap_token)
    node = configuration.get_config().get_node(node_name)
    disk = get_disk_path(node)
    if os.path.exists(disk):
        os.remove(disk)
    if not os.path.isdir(os.path.dirname(disk)):
        os.makedirs(os.path.dirname(disk))
    subprocess.check_call(["qemu-img", "create", "-f", "qcow2", "--", disk, "%uG" % int(disk_gb)])
    # TODO: do something better than a two-second delay to detect "boot:" prompt
    bootline = "install netcfg/get_ipaddress=%s homeworld/asktoken=%s" % (node.ip, bootstrap_token)
    qemu_raw(disk, iso_path, netif=get_node_tap(node), input=bootline, input_delay=2.0, output_to=(None if visible == "show" else "log.%s.install" % node.hostname))


def qemu_launch(node_name, kill_path=None):
    node = configuration.get_config().get_node(node_name)
    disk = get_disk_path(node)
    qemu_raw(disk, netif=get_node_tap(node), output_to=(None if kill_path is None else "log.%s.launch" % node.hostname), kill_path=kill_path)


def qemu_scan_ssh(node_name, kill_path=None):
    node = configuration.get_config().get_node(node_name)
    disk = get_disk_path(node)

    fingerprints = []
    def scan_next(line: bytes):
        if b"SHA256" in line and b" root@temporary-hostname (" in line:
            # TODO: don't just arbitrarily replace the string; parse and do a better conversion (for robustness)
            fingerprints.append(line.strip().decode().replace(" root@temporary-hostname ", " no comment "))
        elif fingerprints and not line.strip():
            access.pull_supervisor_key(fingerprints)
            return True

    qemu_raw(disk, netif=get_node_tap(node), output_callback=scan_next, kill_path=kill_path)


def qemu_wait_for(alive_path):
    notify = time.time()
    last_len = 0
    while not os.path.exists(alive_path):
        message = "waited for server startup for %d seconds" % round(time.time() - notify)
        print(message.ljust(last_len, " "), end="\r")
        time.sleep(1)
        last_len = len(message)
    print("server found".ljust(last_len, " "))


def qemu_check_nested_virt():
    if util.readfile("/sys/module/kvm_intel/parameters/nested").strip() != b"Y":
        command.fail("nested virtualization not enabled")


main_command = seq.seq_mux_map("commands to run local testing VMs", {
    "net": command.mux_map("commands to control the state of the local testing network", {
        "up": command.wrap("bring up local testing network", net_up),
        "down": command.wrap("bring down local testing network", net_down),
    }),
    "qemu": command.mux_map("commands to launch local qemu instances", {
        "install": command.wrap("launch a qemu installation", qemu_install),
        "launch": command.wrap("launch an already-installed qemu instance", qemu_launch),
        "scan-ssh": command.wrap("launch an already-installed qemu instance and update known_hosts based on the printed fingerprint", qemu_scan_ssh),
        "wait-for": command.wrap("wait for scan-ssh to finish getting keys from a node", qemu_wait_for),
        "raw": command.wrap("launch a qemu instance directly, for debugging", qemu_raw),
        "check-nested-virt": command.wrap("check that nested virtualization is available", qemu_check_nested_virt)
    }),
})
