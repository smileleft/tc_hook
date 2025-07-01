1. Execution
    1. File Write
    2. Compile : make
    3. Check Your NIC name
    4. **TC `qdisc` and `filter` configuration (need to root prevelige)**
    
    ```bash
    sudo tc qdisc add dev enp1s0 ingress
    ```
    
    e. BPF filter attach
    
    ```bash
    # sudo tc filter add dev enp1s0 ingress pref 1 handle 1 bpf obj build/tc_block_tcp_kern.bpf.o section classifier flowid 1:1
    sudo tc filter add dev enp1s0 ingress pref 1 handle 1 bpf obj build/tc_block_tcp_kern.bpf.o section classifier direct-action flowid 1:1
    ```
    
2. TC Execution
    1. **Monigoring Kernel Log (New Terminal)**
    
    ```bash
    sudo dmesg -w
    ```
    
    b. Packet Transfer(from another host to IP of `your NIC`)
    
    ```bash
    # If web is running
    curl http://<IP_address>/
    
    # netcat (No response or reject)
    nc -v -w 3 <IP_adress> 80
    ```
    
    c. **Try connection to another TCP port (ex: 22 for SSH)**
    
    ```bash
    nc -v -w 3 <IP_address> 22
    ```
    
3. TC termination (Keep Order)
    1. Remove Filter
    
    ```bash
    sudo tc filter del dev enp1s0 ingress pref 1 handle 1 bpf
    ```
    
    b. Remove `ingress` Qdisc
    
    ```bash
    sudo tc qdisc del dev enp1s0 ingress
    ```
