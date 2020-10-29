import sys, os, time, subprocess
import signal
import argparse

proc_list = []

def cmd(exe, cpu_range, nics, gid):
  port_nums = len(nics) * 2
  # port_binary_str = ''.join(['1' if p in port_range else '0' for p in range(0,8)])[::-1]
  port_binary_str = '0' * (8-port_nums) + '1' * port_nums
  port_hex_str = hex(int(port_binary_str, 2))
  thread_num = len(cpu_range)
  for i in range(thread_num):
    exe_str = 'sudo ' + exe
    arg_str =  f' -l {cpu_range[i]} -n 4 --proc-type=auto --file-prefix=g{gid} '
    for nic in nics:
      arg_str += f'-w {nic}.0 -w {nic}.1 '
    arg_str += f' -- -p {port_hex_str} --num-procs={thread_num} --proc-id={i}'
    # arg_str += ' &'
    print(exe_str+arg_str)
    while True:
      proc = subprocess.Popen([exe_str+arg_str], shell=True)
      # os.system(exe_str+arg_str)
      c = input()
      if c == '':
        proc_list.append(proc)
        break
      proc.terminate()

  print(f'All processes in Group {gid} are running')


def kill(exe):
  for p in proc_list:
    p.terminate()
  print(f'{exe} has been killed')


def exit(signum, frame):
  print('Ready to exit.')
  kill(exe)
  sys.exit(0)


def str2range(s):
  start = int(s.split('-')[0])
  end = int(s.split('-')[1])
  return range(start, end+1)

# python3 run_dpdk.py build/symmetric_mp {c=1-4,p=04:00} {c=5-8,p=2-3}
if __name__ == '__main__':
  assert len(sys.argv) > 2
  signal.signal(signal.SIGINT, exit)
  exe = sys.argv[1]
  for i in range(2, len(sys.argv)):
    cpu_range = None
    nics = []
    try:
      cp_str = sys.argv[i]
      if cp_str[0] == '{':
        cp_str = cp_str[1:-1]

      for p in cp_str.split(','):
        print ()
        key = p.split('=')[0]
        value = p.split('=')[1]
        if key == 'c':
          cpu_range = str2range(value)
        if key == 'p':
          nics.append(value)
    except:
      print (f'Wrong format of group: {sys.argv[i]}')
      exit()
    assert cpu_range is not None and nics is not None
    cmd (exe, cpu_range, nics, i-1)

  print('All processes are running')

  while True:
    pass

