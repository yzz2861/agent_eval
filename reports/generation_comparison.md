# Same-named delay DLL comparison

- left: `sample_a_generation_v1.dll`
- right: `sample_b_generation_v2.dll`

Shared delay-loaded DLLs: appcrt140.dll, kernel32.dll

## Structural evidence differences

| DLL | Symbol | Left evidence classes | Right evidence classes |
| --- | --- | --- | --- |
| appcrt140.dll | `#1234` | ['INDEX_ONLY', 'INDEX_ONLY', 'INDEX_ONLY', 'RUNTIME_UNRESOLVED'] | ['INDEX_ONLY', 'INDEX_ONLY', 'RUNTIME_UNRESOLVED'] |
| appcrt140.dll | `crt_initialize` | ['FILE_POINTER', 'FILE_POINTER', 'FILE_POINTER', 'RUNTIME_UNRESOLVED'] | ['FILE_POINTER', 'FILE_POINTER', 'RUNTIME_UNRESOLVED'] |
| kernel32.dll | `GetLastError` | ['FILE_POINTER', 'FILE_POINTER', 'RUNTIME_UNRESOLVED'] | None |
| kernel32.dll | `Sleep` | ['FILE_POINTER', 'FILE_POINTER', 'RUNTIME_UNRESOLVED'] | ['FILE_POINTER', 'FILE_POINTER', 'FILE_POINTER', 'RUNTIME_UNRESOLVED'] |