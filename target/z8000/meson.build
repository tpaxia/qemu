z8000_ss = ss.source_set()
z8000_system_ss = ss.source_set()

z8000_ss.add(files(
  'translate.c',
  'helper.c',
  'cpu.c'))

target_arch += {'z8000': z8000_ss}
target_system_arch += {'z8000': z8000_system_ss}
