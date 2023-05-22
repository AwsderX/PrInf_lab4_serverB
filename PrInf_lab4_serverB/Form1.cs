using System.Net.Sockets;
using System.Net;
using System.Numerics;
using System.Diagnostics;
using System.Text.RegularExpressions;

namespace PrInf_lab4_serverB
{
    public partial class Form1 : Form
    {
        private const int Port = 8888;
        string privateKeyPath = "C:\\VSProjects\\PrInf_lab4_client\\PrInf_lab4_client\\bin\\Debug\\net6.0-windows\\privatekey.pem";
        string publicKeyPath = "C:\\VSProjects\\PrInf_lab4_client\\PrInf_lab4_client\\bin\\Debug\\net6.0-windows\\publickey.pem";
        public Form1()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs er)
        {           
            // Создание сервера и ожидание подключения клиента
            IPAddress localIpAddress = IPAddress.Parse("127.0.0.1"); // IP-адрес сервера
            TcpListener server = new TcpListener(localIpAddress, Port);
            server.Start();

            TcpClient client = server.AcceptTcpClient();

            // Получение данных от клиента
            NetworkStream stream = client.GetStream();
            byte[] number1Bytes = new byte[client.ReceiveBufferSize];
            int bytesRead1 = stream.Read(number1Bytes, 0, number1Bytes.Length);

            BigInteger number1 = new BigInteger(number1Bytes);

            string privateKeyOutput = ExecuteOpenSSLCommand($"rsa -in {privateKeyPath} -noout -text");
            string publicKeyOutput = ExecuteOpenSSLCommand($"rsa -pubin -in {publicKeyPath} -noout -text");
            BigInteger e, n, d;
            ExtractExponents(privateKeyOutput, publicKeyOutput, out e, out n, out d);
            // Подписание склеенного сообщения
            BigInteger blindedSignature = ModPow(number1, d, n);
            textBox1.Text += "Подписанное сообщение = " + blindedSignature + Environment.NewLine;

            // Преобразование ответа в массив байтов
            byte[] resultBytes = blindedSignature.ToByteArray();

            // Отправка ответа клиенту
            stream.Write(resultBytes, 0, resultBytes.Length);
            server?.Stop();
        }
        private BigInteger ModPow(BigInteger baseValue, BigInteger exponent, BigInteger modulus)
        {
            BigInteger result = 1;
            while (exponent > 0)
            {
                if (exponent % 2 == 1)
                    result = (result * baseValue) % modulus;
                baseValue = (baseValue * baseValue) % modulus;
                exponent /= 2;
            }
            return result;
        }

        private string ExecuteOpenSSLCommand(string arguments)
        {
            string command = "openssl";
            ProcessStartInfo startInfo = new ProcessStartInfo();
            startInfo.FileName = command;
            startInfo.Arguments = arguments;
            startInfo.RedirectStandardOutput = true;

            Process process = new Process();
            process.StartInfo = startInfo;
            process.Start();
            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit(); // Wait for the process to finish
            return output;
        }
        private void ExtractExponents(string output, string output1, out BigInteger e, out BigInteger n, out BigInteger d)
        {
            e = n = d = default;

            for (int i = 0; i < 2; i++)
            {
                string pattern = @"modulus:\s+([\s\S]+?)publicExponent:";
                Match match = Regex.Match(output, pattern);
                if (match.Success)
                {
                    string value = match.Groups[1].Value.Replace(":", "").Replace(" ", "").Replace(Environment.NewLine, "");
                    n = BigInteger.Parse(value, System.Globalization.NumberStyles.HexNumber);
                }

                pattern = @"publicExponent:\s+([\s\S]+?)privateExponent:";
                match = Regex.Match(output, pattern);
                if (match.Success)
                {
                    string value = match.Groups[1].Value.Replace(":", "").Replace(" ", "").Replace(Environment.NewLine, "").Replace("(0x10001)", "");
                    e = BigInteger.Parse(value);
                }

                pattern = @"privateExponent:\s+([\s\S]+?)prime1:";
                match = Regex.Match(output, pattern);
                if (match.Success)
                {
                    string value = match.Groups[1].Value.Replace(":", "").Replace(" ", "").Replace(Environment.NewLine, "");
                    d = BigInteger.Parse(value, System.Globalization.NumberStyles.HexNumber);
                }
                output = output1;
            }
        }
    }
}