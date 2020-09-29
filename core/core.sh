ulimit -c unlimited
//echo "core-%e-%p-%t" > /proc/sys/kernel/core_pattern
//sysctl -w kernel.core_uses_pid=1 
sysctl -w kernel.core_pattern=/data1/core/core.%e.%p.%s.%E
sysctl -w kernel.core_pattern=/data1/core/core.%p
