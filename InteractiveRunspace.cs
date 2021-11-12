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

        private static void runCommand(PowerShell ps, string cmd)
        {
            string getError = "get-variable -value -name Error | Format-Table -Wrap -AutoSize";
            ps.AddScript(cmd);
            ps.AddCommand("Out-String");

            try
            {
                Collection<PSObject> results = ps.Invoke();
                Console.WriteLine(buildOutput(results).ToString().Trim());

                //check for errors
                ps.Commands.Clear();
                ps.AddScript(getError);
                ps.AddCommand("Out-String");
                results = ps.Invoke();
                StringBuilder stringBuilder = buildOutput(results);

                // if $Error holds a value
                if (!String.Equals(stringBuilder.ToString().Trim(), ""))
                {
                    Console.WriteLine(stringBuilder.ToString().Trim());

                    //clear error var
                    ps.Commands.Clear();
                    ps.AddScript("$error.Clear()");
                    ps.Invoke();
                }

            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
            }
            ps.Commands.Clear();
        }

        private static StringBuilder buildOutput(Collection<PSObject> results)
        {
            StringBuilder stringBuilder = new StringBuilder();
            foreach (PSObject obj in results)
            {
                stringBuilder.Append(obj);
            }

            return stringBuilder;
        }

        static void Main(string[] args)
        {
            string cmd;

            //set a large readline input buffer
            const int BufferSize =3000;
            Console.SetIn(new StreamReader(Console.OpenStandardInput(), Encoding.UTF8, false, BufferSize));
            
            Runspace rs = RunspaceFactory.CreateRunspace();
            PowerShell ps = PowerShell.Create();
            rs.Open();
            ps.Runspace = rs;

            while (true)
            {
                Console.Write("PS " + Directory.GetCurrentDirectory() + ">");              
                cmd = Console.ReadLine();
               
                if (String.Equals(cmd, "exit"))
                    break;

                runCommand(ps, cmd);
            }
            rs.Close();
        }
    }
}
