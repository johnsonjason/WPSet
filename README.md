# crb00m

This source sets the cr0 register (control register) and changes the write-copy protection bit and disables it temporarily. The reason for doing this is because:

1) Windows' system modules (DLLs) such as ntdll.dll, kernelbase.dll, etc... use write-copy protection, that is... In the memory, each memory page has a physical address and a corresponding virtual address. System modules will have the same virtual address and share a physical address until the virtual memory has an attempt to be modified. When this occurs, a copy of the underlying physical page is created and the virtual address being written to then maps to that.

2) This all has to occur on the same core

Patching the shared memory for these system modules opens a plethora of opportunities, such as bypassing DRM solutions that run in kernel-mode and have various types of memory integrity protection schemes implemented. This allows for the process the DRM solution is protecting to execute arbitrary code injected by the user.
