if not have_zeus_user
   subdir_done()
endif

# ZEUS (Zilog System 8000 Unix) user-mode emulation.
#
# Every system call is translated to POSIX here, so nothing in this
# directory depends on the host kernel's own system-call interface.  The
# only host-specific part is reading the fault context in a signal handler.

zeus_user_ss = ss.source_set()

if host_os == 'linux' and not have_linux_user
  # host-signal.h for Linux hosts lives with linux-user
  common_user_inc += include_directories('../linux-user/include/host/' / host_arch)
endif

common_user_inc += include_directories('include')

zeus_user_ss.add(files(
  'fpe.c',
  'fs.c',
  'main.c',
  'memory.c',
  'signal.c',
  'sout.c',
  'syscall.c',
))

specific_ss.add_all(when: 'CONFIG_ZEUS_USER', if_true: zeus_user_ss)
