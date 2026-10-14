if not have_user
   subdir_done()
endif

common_user_inc += include_directories('host/' / host_arch)

if host_os == 'darwin'
  # Only zeus-user builds on macOS.  It makes no host system calls of its
  # own and lays out guest memory itself, so it needs none of these.
  subdir_done()
endif

user_ss.add(files(
  'mmap-min-addr.c',
  'probe-guest-base.c',
  'safe-syscall.S',
  'safe-syscall-error.c',
  'selfmap.c',
))
