#ulimit -c unlimited
#echo "core-%e-%p-%t" > /proc/sys/kernel/core_pattern
#sysctl -w kernel.core_uses_pid=1 
#sysctl -w kernel.core_pattern=/data1/core/core.%e.%p.%s.%E
#sysctl -w kernel.core_pattern=/data1/core/core.%p
echo "ulimit -S -c unlimited > /dev/null 2>&1" >> /etc/profile
source /etc/profile
echo "1" > /proc/sys/kernel/core_uses_pid
echo "/data1/core/core-%e-%p_%t" > /proc/sys/kernel/core_pattern
echo "1" > /proc/sys/fs/suid_dumpable
