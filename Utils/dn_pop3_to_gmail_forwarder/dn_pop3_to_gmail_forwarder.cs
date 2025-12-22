// A Program Code
// 
// Copyright (c) 2019- IPA CyberLab.
// Copyright (c) 2003-2018 Daiyuu Nobori.
// Copyright (c) 2013-2018 SoftEther VPN Project, University of Tsukuba, Japan.
// All Rights Reserved.
// 
// License: The Apache License, Version 2.0
// https://www.apache.org/licenses/LICENSE-2.0
// 
// THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// 
// THIS SOFTWARE IS DEVELOPED IN JAPAN, AND DISTRIBUTED FROM JAPAN, UNDER
// JAPANESE LAWS. YOU MUST AGREE IN ADVANCE TO USE, COPY, MODIFY, MERGE, PUBLISH,
// DISTRIBUTE, SUBLICENSE, AND/OR SELL COPIES OF THIS SOFTWARE, THAT ANY
// JURIDICAL DISPUTES WHICH ARE CONCERNED TO THIS SOFTWARE OR ITS CONTENTS,
// AGAINST US (IPA CYBERLAB, DAIYUU NOBORI, SOFTETHER VPN PROJECT OR OTHER
// SUPPLIERS), OR ANY JURIDICAL DISPUTES AGAINST US WHICH ARE CAUSED BY ANY KIND
// OF USING, COPYING, MODIFYING, MERGING, PUBLISHING, DISTRIBUTING, SUBLICENSING,
// AND/OR SELLING COPIES OF THIS SOFTWARE SHALL BE REGARDED AS BE CONSTRUED AND
// CONTROLLED BY JAPANESE LAWS, AND YOU MUST FURTHER CONSENT TO EXCLUSIVE
// JURISDICTION AND VENUE IN THE COURTS SITTING IN TOKYO, JAPAN. YOU MUST WAIVE
// ALL DEFENSES OF LACK OF PERSONAL JURISDICTION AND FORUM NON CONVENIENS.
// PROCESS MAY BE SERVED ON EITHER PARTY IN THE MANNER AUTHORIZED BY APPLICABLE
// LAW OR COURT RULE.

// Author: Daiyuu Nobori

#if true

#pragma warning disable CA2235 // Mark all non-serializable fields

using System;
using System.Buffers;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.Serialization;
using System.CommandLine;
using System.CommandLine.Invocation;

namespace dn_pop3_to_gmail_forwarder;

public class Program
{
    /// <summary>
    /// エントリポイント (Main 関数) です。
    /// </summary>
    /// <param name="args">コマンドライン引数です。</param>
    /// <returns>プロセス戻り値です。(0: 成功 / 1: 失敗)</returns>
    public static async Task<int> Main(string[] args)
    {
        try
        {
            // ★ 旧来エンコーディング (ISO-2022-JP / Shift JIS 等) 対応のため、プログラム初期化時に登録する (規約 111. テキスト処理 [WUZK8R3U])
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

            RootCommand rootCommand = BuildRootCommand();

            if (args.Length == 0)
            {
                await rootCommand.InvokeAsync(new[] { "--help" }).ConfigureAwait(false);
                return 1;
            }

            return await rootCommand.InvokeAsync(args).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.ToString());
            return 1;
        }
    }

    /// <summary>
    /// コマンドライン定義を構築します。(251218_K3VRU3 パターン)
    /// </summary>
    /// <returns>ルートコマンドです。</returns>
    private static RootCommand BuildRootCommand()
    {
        var root = new RootCommand("dn_pop3_to_gmail_forwarder: import POP3 mailbox messages into Gmail (via Gmail API).");

        var getTokenCommand = new Command("gettoken", "Get Gmail OAuth token JSON (desktop/native app loopback flow).");

        var saveAsOption = new Option<string>("--saveas", "Output token JSON file path.") { IsRequired = true };
        var clientIdOption = new Option<string>("--client_id", "Gmail API client_id.") { IsRequired = true };
        var clientSecretOption = new Option<string>("--client_secret", "Gmail API client_secret.") { IsRequired = true };
        var portOption = new Option<int>("--port", "Local loopback HTTP port (127.0.0.1).") { IsRequired = true };

        getTokenCommand.AddOption(saveAsOption);
        getTokenCommand.AddOption(clientIdOption);
        getTokenCommand.AddOption(clientSecretOption);
        getTokenCommand.AddOption(portOption);

        getTokenCommand.SetHandler(async (InvocationContext context) =>
        {
            string saveAs = context.ParseResult.GetValueForOption(saveAsOption) ?? "";
            string clientId = context.ParseResult.GetValueForOption(clientIdOption) ?? "";
            string clientSecret = context.ParseResult.GetValueForOption(clientSecretOption) ?? "";
            int port = context.ParseResult.GetValueForOption(portOption);

            var options = new FeatureGetToken.GetTokenOptions
            {
                SaveAsPath = saveAs,
                ClientId = clientId,
                ClientSecret = clientSecret,
                Port = port,
            };

            context.ExitCode = await FeatureGetToken.RunAsync(options).ConfigureAwait(false);
        });

        var forwardCommand = new Command("forward", "Forward mode: import POP3 mailbox messages into Gmail.");

        var configOption = new Option<string>("--config", "Forward mode TOML config file path.") { IsRequired = true };
        forwardCommand.AddOption(configOption);

        forwardCommand.SetHandler(async (InvocationContext context) =>
        {
            string configPath = context.ParseResult.GetValueForOption(configOption) ?? "";

            var options = new FeatureForward.ForwardOptions
            {
                ConfigPath = configPath,
            };

            context.ExitCode = await FeatureForward.RunAsync(options).ConfigureAwait(false);
        });

        root.AddCommand(getTokenCommand);
        root.AddCommand(forwardCommand);

        var checkCommand = new Command("check", "Check mode: validate config without network access.");
        var checkConfigOption = new Option<string>("--config", "Check mode TOML config file path.") { IsRequired = true };
        checkCommand.AddOption(checkConfigOption);

        checkCommand.SetHandler(async (InvocationContext context) =>
        {
            string configPath = context.ParseResult.GetValueForOption(checkConfigOption) ?? "";

            var options = new FeatureCheck.CheckOptions
            {
                ConfigPath = configPath,
            };

            context.ExitCode = await FeatureCheck.RunAsync(options).ConfigureAwait(false);
        });

        root.AddCommand(checkCommand);

        return root;
    }
}

#endif


