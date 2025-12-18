// Author: Daiyuu Nobori
// Created: 2025-12-18
// Powered by AI: GPT-5.2

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
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using Newtonsoft.Json.Linq;

namespace dn_pop3_to_gmail_forwarder;

/// <summary>
/// gettoken モード [F3QBRBA9] の機能実装です。
/// </summary>
public static class FeatureGetToken
{
    /// <summary>
    /// gettoken モードの実行パラメータです。
    /// </summary>
    public sealed class GetTokenOptions
    {
        /// <summary>
        /// 結果初期トークン JSON ファイルの保存先パスです。
        /// </summary>
        public string SaveAsPath = "";

        /// <summary>
        /// Gmail API に対して予めユーザが登録しておいたクライアントアプリ ID です。
        /// </summary>
        public string ClientId = "";

        /// <summary>
        /// クライアントシークレットです。
        /// </summary>
        public string ClientSecret = "";

        /// <summary>
        /// Loopback (127.0.0.1) HTTP サーバーの待受ポート番号です。
        /// </summary>
        public int Port;
    }

    /// <summary>
    /// Gmail との OAuth トークン情報 JSON データ [EG8R7RTE] です。
    /// </summary>
    public sealed class GMailOAuthTokenJsonData
    {
        /// <summary>
        /// 最後に更新された日時です。
        /// </summary>
        public DateTimeOffset LastRefreshDt;

        /// <summary>
        /// クライアントアプリ ID です。
        /// </summary>
        public string AppClientId = "";

        /// <summary>
        /// クライアントシークレットです。
        /// </summary>
        public string AppClientSecret = "";

        /// <summary>
        /// アクセストークン (必要に応じて更新される) です。
        /// </summary>
        public string UserAccessToken = "";
    }

    /// <summary>
    /// gettoken モードを実行します。
    /// </summary>
    /// <param name="options">実行パラメータです。</param>
    /// <param name="cancel">キャンセル要求です。</param>
    /// <returns>プロセス戻り値です。(0: 成功 / 1: 失敗)</returns>
    public static async Task<int> RunAsync(GetTokenOptions options, CancellationToken cancel = default)
    {
        if (options == null) throw new ArgumentNullException(nameof(options));

        ValidateOptions(options);

        using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(cancel);

        ConsoleCancelEventHandler? handler = null;
        handler = (sender, e) =>
        {
            e.Cancel = true;
            try
            {
                cts.Cancel();
            }
            catch { }
        };

        Console.CancelKeyPress += handler;

        try
        {
            string redirectUri = $"http://127.0.0.1:{options.Port}/auth_callback";
            string startUrl = $"http://127.0.0.1:{options.Port}/start";

            string state = GenerateStateToken();

            TcpListener listener = new TcpListener(IPAddress.Loopback, options.Port);
            listener.Start();

            Console.WriteLine($"Loopback HTTP server started. Open this URL in your browser: {startUrl}");

            using var reg = cts.Token.Register(() =>
            {
                try { listener.Stop(); } catch { }
            });

            while (cts.IsCancellationRequested == false)
            {
                TcpClient? clientNullable = null;
                try
                {
                    clientNullable = await listener.AcceptTcpClientAsync().ConfigureAwait(false);
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
                catch (SocketException)
                {
                    if (cts.IsCancellationRequested) break;
                    throw;
                }

                TcpClient client = clientNullable ?? throw new Exception("APPERROR: AcceptTcpClientAsync returned null.");

                _ = Task.Run(async () =>
                {
                    using (client)
                    {
                        try
                        {
                            await HandleClientAsync(client, options, redirectUri, state, cts.Token).ConfigureAwait(false);
                        }
                        catch (OperationCanceledException) when (cts.IsCancellationRequested)
                        {
                        }
                        catch (Exception ex)
                        {
                            try
                            {
                                await TryWriteInternalServerErrorAsync(client, ex, cts.Token).ConfigureAwait(false);
                            }
                            catch { }
                        }
                    }
                });
            }

            return 0;
        }
        finally
        {
            try { cts.Cancel(); } catch { }
            try { Console.WriteLine("Stopping loopback HTTP server..."); } catch { }

            if (handler != null)
            {
                Console.CancelKeyPress -= handler;
            }
        }
    }

    /// <summary>
    /// gettoken オプションの妥当性を検査します。
    /// </summary>
    /// <param name="options">実行パラメータです。</param>
    private static void ValidateOptions(GetTokenOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.SaveAsPath))
            throw new Exception("APPERROR: --saveas is required.");

        if (string.IsNullOrWhiteSpace(options.ClientId))
            throw new Exception("APPERROR: --client_id is required.");

        if (string.IsNullOrWhiteSpace(options.ClientSecret))
            throw new Exception("APPERROR: --client_secret is required.");

        if (options.Port <= 0 || options.Port >= 65536)
            throw new Exception("APPERROR: --port must be in range 1..65535.");
    }

    /// <summary>
    /// 1 つの TCP クライアント接続を処理します。
    /// </summary>
    /// <param name="client">TCP クライアントです。</param>
    /// <param name="options">gettoken 実行パラメータです。</param>
    /// <param name="redirectUri">OAuth リダイレクト URI です。</param>
    /// <param name="state">CSRF 対策用 state トークンです。</param>
    /// <param name="cancel">キャンセル要求です。</param>
    /// <returns>完了タスクです。</returns>
    private static async Task HandleClientAsync(TcpClient client, GetTokenOptions options, string redirectUri, string state, CancellationToken cancel)
    {
        client.NoDelay = true;
        client.ReceiveTimeout = 30_000;
        client.SendTimeout = 30_000;

        using NetworkStream stream = client.GetStream();

        SimpleHttpRequest request = await ReadHttpRequestAsync(stream, cancel).ConfigureAwait(false);

        switch (request.Path)
        {
            case "/":
            case "/start":
                await HandleStartAsync(stream, options, redirectUri, state, cancel).ConfigureAwait(false);
                return;

            case "/auth_callback":
                await HandleAuthCallbackAsync(stream, request, options, redirectUri, state, cancel).ConfigureAwait(false);
                return;

            default:
                await WriteHtmlResponseAsync(stream, 404, BuildNotFoundHtml(), cancel).ConfigureAwait(false);
                return;
        }
    }

    /// <summary>
    /// /start を処理します。
    /// </summary>
    /// <param name="stream">接続ストリームです。</param>
    /// <param name="options">gettoken 実行パラメータです。</param>
    /// <param name="redirectUri">OAuth リダイレクト URI です。</param>
    /// <param name="state">CSRF 対策用 state トークンです。</param>
    /// <param name="cancel">キャンセル要求です。</param>
    /// <returns>完了タスクです。</returns>
    private static async Task HandleStartAsync(Stream stream, GetTokenOptions options, string redirectUri, string state, CancellationToken cancel)
    {
        string authUrl = BuildGoogleAuthUrl(options.ClientId, redirectUri, state);
        string html = BuildStartHtml(authUrl, redirectUri);
        await WriteHtmlResponseAsync(stream, 200, html, cancel).ConfigureAwait(false);
    }

    /// <summary>
    /// /auth_callback を処理します。
    /// </summary>
    /// <param name="stream">接続ストリームです。</param>
    /// <param name="request">HTTP リクエストです。</param>
    /// <param name="options">gettoken 実行パラメータです。</param>
    /// <param name="redirectUri">OAuth リダイレクト URI です。</param>
    /// <param name="expectedState">期待する state トークンです。</param>
    /// <param name="cancel">キャンセル要求です。</param>
    /// <returns>完了タスクです。</returns>
    private static async Task HandleAuthCallbackAsync(Stream stream, SimpleHttpRequest request, GetTokenOptions options, string redirectUri, string expectedState, CancellationToken cancel)
    {
        if (request.Query.TryGetValue("error", out string? error) && string.IsNullOrWhiteSpace(error) == false)
        {
            string desc = request.Query.TryGetValue("error_description", out string? errorDesc) ? errorDesc : "";
            await WriteHtmlResponseAsync(stream, 200, BuildErrorHtml($"OAuth error: {error}. {desc}".Trim()), cancel).ConfigureAwait(false);
            return;
        }

        if (request.Query.TryGetValue("state", out string? state) == false || string.Equals(state, expectedState, StringComparison.Ordinal) == false)
        {
            await WriteHtmlResponseAsync(stream, 400, BuildErrorHtml("APPERROR: Invalid state parameter."), cancel).ConfigureAwait(false);
            return;
        }

        if (request.Query.TryGetValue("code", out string? code) == false || string.IsNullOrWhiteSpace(code))
        {
            await WriteHtmlResponseAsync(stream, 400, BuildErrorHtml("APPERROR: Missing authorization code."), cancel).ConfigureAwait(false);
            return;
        }

        string accessToken = await ExchangeCodeForAccessTokenAsync(code, options, redirectUri, cancel).ConfigureAwait(false);

        string saveAsFullPath = Path.GetFullPath(options.SaveAsPath);

        var data = new GMailOAuthTokenJsonData
        {
            LastRefreshDt = DateTimeOffset.Now,
            AppClientId = options.ClientId,
            AppClientSecret = options.ClientSecret,
            UserAccessToken = accessToken,
        };

        await WriteTokenFileAsync(saveAsFullPath, data, cancel).ConfigureAwait(false);

        string html = BuildSuccessHtml(saveAsFullPath);
        await WriteHtmlResponseAsync(stream, 200, html, cancel).ConfigureAwait(false);

        Console.WriteLine($"Token JSON saved: {saveAsFullPath}");
        Console.WriteLine("You can close the browser now. Press Ctrl+C to exit this program.");
    }

    /// <summary>
    /// OAuth の authorization code をアクセストークンに交換します。
    /// </summary>
    /// <param name="authorizationCode">Authorization code です。</param>
    /// <param name="options">gettoken 実行パラメータです。</param>
    /// <param name="redirectUri">OAuth リダイレクト URI です。</param>
    /// <param name="cancel">キャンセル要求です。</param>
    /// <returns>アクセストークン文字列です。</returns>
    private static async Task<string> ExchangeCodeForAccessTokenAsync(string authorizationCode, GetTokenOptions options, string redirectUri, CancellationToken cancel)
    {
        // Google OAuth 2.0 Token Endpoint
        const string tokenEndpoint = "https://oauth2.googleapis.com/token";

        using var httpClient = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(30),
        };

        using var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["code"] = authorizationCode,
            ["client_id"] = options.ClientId,
            ["client_secret"] = options.ClientSecret,
            ["redirect_uri"] = redirectUri,
            ["grant_type"] = "authorization_code",
        });

        using HttpResponseMessage resp = await httpClient.PostAsync(tokenEndpoint, content, cancel).ConfigureAwait(false);
        string body = await resp.Content.ReadAsStringAsync(cancel).ConfigureAwait(false);

        if (resp.IsSuccessStatusCode == false)
        {
            throw new Exception($"APPERROR: OAuth token endpoint returned {(int)resp.StatusCode} {resp.ReasonPhrase}. Body: {body}");
        }

        JObject json;
        try
        {
            json = JObject.Parse(body);
        }
        catch (Exception ex)
        {
            throw new Exception($"APPERROR: Failed to parse token endpoint JSON response. Body: {body}", ex);
        }

        string? accessToken = json.Value<string>("access_token");
        if (string.IsNullOrWhiteSpace(accessToken))
        {
            throw new Exception($"APPERROR: Token endpoint response does not contain access_token. Body: {body}");
        }

        return accessToken;
    }

    /// <summary>
    /// OAuth トークン JSON ファイルを書き込みます。(テンポラリ経由の置換)
    /// </summary>
    /// <param name="saveAsFullPath">保存先フルパスです。</param>
    /// <param name="data">保存する JSON データです。</param>
    /// <param name="cancel">キャンセル要求です。</param>
    /// <returns>完了タスクです。</returns>
    private static async Task WriteTokenFileAsync(string saveAsFullPath, GMailOAuthTokenJsonData data, CancellationToken cancel)
    {
        // ★ JSON 書き出し規約 [PV4U3JTR] を共通処理化したものを使用する
        await LibCommon.WriteSingleJsonFileByTempAsync(saveAsFullPath, data, cancel).ConfigureAwait(false);
    }

    /// <summary>
    /// 簡易 HTTP リクエストです。(本機能に必要な最小限のみ)
    /// </summary>
    private sealed class SimpleHttpRequest
    {
        /// <summary>
        /// HTTP メソッドです。(例: GET)
        /// </summary>
        public string Method = "";

        /// <summary>
        /// リクエストターゲット (生) です。
        /// </summary>
        public string RawTarget = "";

        /// <summary>
        /// パス部分です。(例: /start)
        /// </summary>
        public string Path = "";

        /// <summary>
        /// クエリ文字列を解析したディクショナリです。
        /// </summary>
        public IReadOnlyDictionary<string, string> Query = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// HTTP リクエストを読み取ります。(GET のみ想定)
    /// </summary>
    /// <param name="stream">読み取りストリームです。</param>
    /// <param name="cancel">キャンセル要求です。</param>
    /// <returns>簡易 HTTP リクエストです。</returns>
    private static async Task<SimpleHttpRequest> ReadHttpRequestAsync(Stream stream, CancellationToken cancel)
    {
        // ★ 最小限の HTTP/1.1 パーサー (GET だけ想定)
        using var reader = new StreamReader(stream, Encoding.ASCII, detectEncodingFromByteOrderMarks: false, bufferSize: 4096, leaveOpen: true);

        string? requestLine = await reader.ReadLineAsync().WaitAsync(cancel).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(requestLine))
            throw new Exception("APPERROR: Invalid HTTP request line.");

        string[] parts = requestLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2)
            throw new Exception("APPERROR: Invalid HTTP request line.");

        string method = parts[0].Trim();
        string rawTarget = parts[1].Trim();

        // Read and ignore headers
        while (true)
        {
            string? line = await reader.ReadLineAsync().WaitAsync(cancel).ConfigureAwait(false);
            if (line == null) break;
            if (line.Length == 0) break;
        }

        Uri uri = rawTarget.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || rawTarget.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
            ? new Uri(rawTarget)
            : new Uri("http://127.0.0.1" + rawTarget);

        return new SimpleHttpRequest
        {
            Method = method,
            RawTarget = rawTarget,
            Path = uri.AbsolutePath,
            Query = ParseQueryString(uri.Query),
        };
    }

    /// <summary>
    /// クエリ文字列 (?a=b&amp;c=d) を解析します。
    /// </summary>
    /// <param name="query">クエリ文字列です。(先頭の ? を含んでもよい)</param>
    /// <returns>解析結果ディクショナリです。</returns>
    private static IReadOnlyDictionary<string, string> ParseQueryString(string query)
    {
        Dictionary<string, string> ret = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        if (string.IsNullOrEmpty(query))
            return ret;

        string q = query.StartsWith("?") ? query.Substring(1) : query;
        foreach (string part in q.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            string[] kv = part.Split('=', 2);
            string name = WebUtility.UrlDecode(kv[0]) ?? "";
            string value = kv.Length >= 2 ? (WebUtility.UrlDecode(kv[1]) ?? "") : "";
            if (string.IsNullOrEmpty(name) == false)
            {
                ret[name] = value;
            }
        }

        return ret;
    }

    /// <summary>
    /// HTML を HTTP レスポンスとして書き込みます。
    /// </summary>
    /// <param name="stream">書き込みストリームです。</param>
    /// <param name="statusCode">HTTP ステータスコードです。</param>
    /// <param name="htmlBody">HTML 本文です。</param>
    /// <param name="cancel">キャンセル要求です。</param>
    /// <returns>完了タスクです。</returns>
    private static async Task WriteHtmlResponseAsync(Stream stream, int statusCode, string htmlBody, CancellationToken cancel)
    {
        byte[] body = Encoding.UTF8.GetBytes(htmlBody);
        string statusText = GetStatusText(statusCode);

        string headers =
            $"HTTP/1.1 {statusCode} {statusText}\r\n" +
            "Content-Type: text/html; charset=utf-8\r\n" +
            $"Content-Length: {body.Length}\r\n" +
            "Connection: close\r\n" +
            "\r\n";

        byte[] headerBytes = Encoding.ASCII.GetBytes(headers);

        await stream.WriteAsync(headerBytes, 0, headerBytes.Length, cancel).ConfigureAwait(false);
        await stream.WriteAsync(body, 0, body.Length, cancel).ConfigureAwait(false);
        await stream.FlushAsync(cancel).ConfigureAwait(false);
    }

    /// <summary>
    /// HTTP ステータスコードから、最小限のステータステキストを返します。
    /// </summary>
    /// <param name="statusCode">HTTP ステータスコードです。</param>
    /// <returns>ステータステキストです。</returns>
    private static string GetStatusText(int statusCode)
    {
        return statusCode switch
        {
            200 => "OK",
            302 => "Found",
            400 => "Bad Request",
            404 => "Not Found",
            500 => "Internal Server Error",
            _ => "OK",
        };
    }

    /// <summary>
    /// Google OAuth 認証開始 URL を生成します。
    /// </summary>
    /// <param name="clientId">クライアント ID です。</param>
    /// <param name="redirectUri">リダイレクト URI です。</param>
    /// <param name="state">CSRF 対策用 state トークンです。</param>
    /// <returns>認証開始 URL です。</returns>
    private static string BuildGoogleAuthUrl(string clientId, string redirectUri, string state)
    {
        // 参考: https://developers.google.com/identity/protocols/oauth2/native-app
        const string endpoint = "https://accounts.google.com/o/oauth2/v2/auth";

        string scope = "https://www.googleapis.com/auth/gmail.modify";

        var query = new Dictionary<string, string>
        {
            ["client_id"] = clientId,
            ["redirect_uri"] = redirectUri,
            ["response_type"] = "code",
            ["scope"] = scope,
            ["state"] = state,
            ["access_type"] = "offline",
            ["prompt"] = "consent",
        };

        var sb = new StringBuilder();
        bool first = true;
        foreach (var kv in query)
        {
            if (first == false) sb.Append('&');
            first = false;
            sb.Append(Uri.EscapeDataString(kv.Key));
            sb.Append('=');
            sb.Append(Uri.EscapeDataString(kv.Value));
        }

        return endpoint + "?" + sb.ToString();
    }

    /// <summary>
    /// /start の HTML を生成します。
    /// </summary>
    /// <param name="authUrl">Google 認証開始 URL です。</param>
    /// <param name="redirectUri">リダイレクト URI です。</param>
    /// <returns>HTML 文字列です。</returns>
    private static string BuildStartHtml(string authUrl, string redirectUri)
    {
        string safeAuthUrl = HtmlEncode(authUrl);
        string safeRedirect = HtmlEncode(redirectUri);

        return $@"<!doctype html>
<html>
<head>
  <meta charset=""utf-8"" />
  <title>dn_pop3_to_gmail_forwarder - gettoken</title>
  <style>
    body {{ font-family: sans-serif; margin: 24px; line-height: 1.5; }}
    .box {{ max-width: 900px; padding: 20px; border: 1px solid #ddd; border-radius: 10px; }}
    a.button {{ display: inline-block; padding: 10px 16px; border-radius: 8px; background: #1a73e8; color: white; text-decoration: none; }}
    code {{ background: #f6f8fa; padding: 2px 6px; border-radius: 6px; }}
  </style>
</head>
<body>
  <div class=""box"">
    <h1>Gmail OAuth Token Setup</h1>
    <p>This page starts the OAuth flow for <code>gmail.modify</code>.</p>
    <p>Redirect URI: <code>{safeRedirect}</code></p>
    <p><a class=""button"" href=""{safeAuthUrl}"">Start</a></p>
    <p style=""margin-top: 24px; color: #666;"">This server listens only on <code>127.0.0.1</code>.</p>
  </div>
</body>
</html>";
    }

    /// <summary>
    /// /auth_callback 成功時の HTML を生成します。
    /// </summary>
    /// <param name="saveAsFullPath">保存先フルパスです。</param>
    /// <returns>HTML 文字列です。</returns>
    private static string BuildSuccessHtml(string saveAsFullPath)
    {
        string safePath = HtmlEncode(saveAsFullPath);

        return $@"<!doctype html>
<html>
<head>
  <meta charset=""utf-8"" />
  <title>Token Saved</title>
  <style>
    body {{ font-family: sans-serif; margin: 24px; line-height: 1.5; }}
    .box {{ max-width: 900px; padding: 20px; border: 1px solid #ddd; border-radius: 10px; }}
    button {{ padding: 10px 16px; border-radius: 8px; border: 1px solid #ccc; background: #fff; }}
    code {{ background: #f6f8fa; padding: 2px 6px; border-radius: 6px; }}
  </style>
</head>
<body>
  <div class=""box"">
    <h1>Done!</h1>
    <p>The OAuth token JSON file has been saved to:</p>
    <p><code>{safePath}</code></p>
    <p>You can close this browser tab now.</p>
    <p><button onclick=""window.close();"">Close Tab</button></p>
    <p style=""margin-top: 24px; color: #666;"">If the tab does not close automatically, just close it manually.</p>
  </div>
</body>
</html>";
    }

    /// <summary>
    /// エラー時の HTML を生成します。
    /// </summary>
    /// <param name="message">エラーメッセージです。</param>
    /// <returns>HTML 文字列です。</returns>
    private static string BuildErrorHtml(string message)
    {
        string safe = HtmlEncode(message);

        return $@"<!doctype html>
<html>
<head>
  <meta charset=""utf-8"" />
  <title>Error</title>
  <style>
    body {{ font-family: sans-serif; margin: 24px; line-height: 1.5; }}
    .box {{ max-width: 900px; padding: 20px; border: 1px solid #f5c2c7; background: #f8d7da; border-radius: 10px; }}
    code {{ background: rgba(255,255,255,0.6); padding: 2px 6px; border-radius: 6px; }}
  </style>
</head>
<body>
  <div class=""box"">
    <h1>OAuth Error</h1>
    <p><code>{safe}</code></p>
    <p>Please close this tab and check the console output.</p>
  </div>
</body>
</html>";
    }

    /// <summary>
    /// 404 用 HTML を生成します。
    /// </summary>
    /// <returns>HTML 文字列です。</returns>
    private static string BuildNotFoundHtml()
    {
        return @"<!doctype html>
<html>
<head><meta charset=""utf-8"" /><title>Not Found</title></head>
<body><h1>404 Not Found</h1></body>
</html>";
    }

    /// <summary>
    /// HTML エンコードを行ないます。
    /// </summary>
    /// <param name="s">入力文字列です。</param>
    /// <returns>HTML エンコード済み文字列です。</returns>
    private static string HtmlEncode(string s)
    {
        return WebUtility.HtmlEncode(s) ?? "";
    }

    /// <summary>
    /// CSRF 対策用の state トークンを生成します。
    /// </summary>
    /// <returns>state トークンです。</returns>
    private static string GenerateStateToken()
    {
        byte[] data = new byte[32];
        RandomNumberGenerator.Fill(data);
        return Base64UrlEncode(data);
    }

    /// <summary>
    /// Base64URL エンコードを行ないます。(RFC 4648)
    /// </summary>
    /// <param name="data">入力バイト列です。</param>
    /// <returns>Base64URL 文字列です。</returns>
    private static string Base64UrlEncode(byte[] data)
    {
        string s = Convert.ToBase64String(data);
        s = s.Replace('+', '-').Replace('/', '_').TrimEnd('=');
        return s;
    }

    /// <summary>
    /// 可能であれば、500 エラー HTML を返信します。
    /// </summary>
    /// <param name="client">TCP クライアントです。</param>
    /// <param name="ex">例外です。</param>
    /// <param name="cancel">キャンセル要求です。</param>
    /// <returns>完了タスクです。</returns>
    private static async Task TryWriteInternalServerErrorAsync(TcpClient client, Exception ex, CancellationToken cancel)
    {
        try
        {
            using NetworkStream stream = client.GetStream();
            await WriteHtmlResponseAsync(stream, 500, BuildErrorHtml("APPERROR: Internal error occurred. " + ex.Message), cancel).ConfigureAwait(false);
        }
        catch { }
    }
}

#endif
