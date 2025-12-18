// Author: Daiyuu Nobori
// Created: 2025-12-18
// Powered by AI: GPT-5.2

#if true

#pragma warning disable CA2235 // Mark all non-serializable fields

using System;
using System.Buffers;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Mail;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using MimeKit;
using MimeKit.Utils;
using Newtonsoft.Json;
using Tomlyn;
using Tomlyn.Model;

namespace dn_pop3_to_gmail_forwarder;

/// <summary>
/// forward モード (メール転送実施モード) [AC579L84] の機能実装です。
/// </summary>
public static class FeatureForward
{
    /// <summary>
    /// forward モードの実行パラメータです。
    /// </summary>
    public sealed class ForwardOptions
    {
        /// <summary>
        /// forward モード用の TOML 設定ファイルパスです。
        /// </summary>
        public string ConfigPath = "";
    }

    /// <summary>
    /// forward モードを実行します。
    /// </summary>
    /// <param name="options">実行パラメータです。</param>
    /// <param name="cancel">キャンセル要求です。</param>
    /// <returns>プロセス戻り値です。(0: 成功 / 1: 失敗)</returns>
    public static async Task<int> RunAsync(ForwardOptions options, CancellationToken cancel = default)
    {
        if (options == null) throw new ArgumentNullException(nameof(options));

        ForwardLogger? logger = null;

        try
        {
            ValidateOptions(options);

            ForwardConfig config = await LoadConfigAsync(options.ConfigPath, cancel).ConfigureAwait(false);

            logger = new ForwardLogger(config.Generic.LogDir);

            logger.Info($"forward mode started. config = {config.ConfigFilePath}");

            await RunForwardInternalAsync(config, logger, cancel).ConfigureAwait(false);

            logger.Info("forward mode finished successfully.");

            return 0;
        }
        catch (OperationCanceledException)
        {
            // Ctrl+C 等で停止した場合はエラー扱いとする
            if (logger != null)
            {
                logger.Error("APPERROR: Canceled.");
            }
            else
            {
                try { ForwardLogger.WriteErrorToConsoleOnly("APPERROR: Canceled."); } catch { }
            }
            return 1;
        }
        catch (Exception ex)
        {
            // forward モードでは、Error ログ形式でユーザーに通知する (可能ならログファイルにも保存する)
            string msg = ex.Message ?? "Unknown error.";
            if (msg.StartsWith("APPERROR:", StringComparison.OrdinalIgnoreCase) == false)
            {
                msg = "APPERROR: " + msg;
            }

            if (logger != null)
            {
                logger.Error(msg);
            }
            else
            {
                try { ForwardLogger.WriteErrorToConsoleOnly(msg); } catch { }
            }

            return 1;
        }
    }

    /// <summary>
    /// forward オプションの妥当性を検査します。
    /// </summary>
    /// <param name="options">実行パラメータです。</param>
    private static void ValidateOptions(ForwardOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.ConfigPath))
        {
            throw new Exception("APPERROR: --config is required.");
        }
    }

    /// <summary>
    /// forward のメイン処理を実行します。
    /// </summary>
    /// <param name="config">設定データです。</param>
    /// <param name="logger">ロガーです。</param>
    /// <param name="cancel">キャンセル要求です。</param>
    private static async Task RunForwardInternalAsync(ForwardConfig config, ForwardLogger logger, CancellationToken cancel)
    {
        // POP3 の残りメールがすべて無くなるまで繰り返す
        int totalProcessed = 0;

        while (true)
        {
            cancel.ThrowIfCancellationRequested();

            logger.Info($"Connecting POP3 server: {config.Pop3.Hostname}:{config.Pop3.Port}, ssl_mode={config.Pop3.SslMode}, verify_cert={config.Pop3.SslVerifyServerCert}, user={config.Pop3.Username}");

            await using Pop3Client pop3 = await Pop3Client.ConnectAndLoginAsync(config.Pop3, logger, cancel).ConfigureAwait(false);

            (int messageCount, int totalSize) = await pop3.StatAsync(cancel).ConfigureAwait(false);

            logger.Info($"POP3 STAT: messages={messageCount}, total_size={totalSize}");

            if (messageCount <= 0)
            {
                logger.Info("No messages on POP3 server.");
                return;
            }

            int processedThisLogin = 0;
            int totalThisLogin = messageCount;

            while (processedThisLogin < config.Pop3.MaxBatchMailsPerLogin)
            {
                cancel.ThrowIfCancellationRequested();

                (int currentCount, _) = await pop3.StatAsync(cancel).ConfigureAwait(false);
                if (currentCount <= 0)
                {
                    logger.Info("No more messages on POP3 server in this session.");
                    break;
                }

                int indexInThisLogin = processedThisLogin + 1;

                // ★ 1 セッション内では、常に 1 番目のメッセージを処理し続ける (削除したものは QUIT で反映され、再ログイン後も継続可能)
                int messageNo = 1;

                logger.Info($"POP3 RETR: index={indexInThisLogin}/{totalThisLogin}, msg_no={messageNo}, remaining={currentCount}");

                byte[] rawMail = await pop3.RetrieveMessageAsync(messageNo, cancel).ConfigureAwait(false);

                logger.Info($"POP3 RETR OK: size={rawMail.Length}");

                DateTimeOffset fetchedNow = DateTimeOffset.Now;

                MailMetaData meta = ParseMailMetaDataBestEffort(rawMail, fetchedNow);

                logger.Info(BuildMailMetaSummary("POP3 mail meta", meta));

                await SaveArchiveAsync(config, meta, rawMail, fetchedNow, logger, cancel).ConfigureAwait(false);

                // Gmail 転送 (大きすぎる場合はスキップ)
                if (rawMail.Length > config.Gmail.GmailMaxMailSize)
                {
                    logger.Error(BuildMailMetaSummary($"Mail size exceeds gmail_max_mail_size={config.Gmail.GmailMaxMailSize}. Gmail import skipped", meta));
                }
                else
                {
                    string accessToken = await EnsureGmailAccessTokenAsync(config, logger, cancel).ConfigureAwait(false);
                    await GmailApiImportAsync(config, accessToken, rawMail, cancel).ConfigureAwait(false);
                    logger.Info(BuildMailMetaSummary("Gmail import completed", meta));
                }

                // POP3 削除
                await pop3.DeleteMessageAsync(messageNo, cancel).ConfigureAwait(false);
                logger.Info(BuildMailMetaSummary("POP3 DELE completed", meta));

                processedThisLogin++;
                totalProcessed++;
            }

            // max_batch_mails_per_login を超えた場合は、QUIT して再ログインする
            if (processedThisLogin >= config.Pop3.MaxBatchMailsPerLogin)
            {
                logger.Info($"Reached max_batch_mails_per_login={config.Pop3.MaxBatchMailsPerLogin}. Re-login to POP3.");
            }
        }
    }

    /// <summary>
    /// メールのメタデータを、可能な範囲でパースして生成します。[Q9MZU6D5]
    /// </summary>
    /// <param name="rawMail">POP3 から取得したメールの生データです。</param>
    /// <param name="fetchedNow">取得時刻です。(DateTime_Received 不明時の代替)</param>
    /// <returns>生成されたメタデータです。</returns>
    private static MailMetaData ParseMailMetaDataBestEffort(byte[] rawMail, DateTimeOffset fetchedNow)
    {
        if (rawMail == null) throw new ArgumentNullException(nameof(rawMail));

        var meta = new MailMetaData
        {
            MailSize = rawMail.Length,
            Subject = "",
            DateTime_Header = null,
            DateTime_Received = null,
            MessageId = "",
            AddressList_From = null,
            AddressList_To = new List<MailAddress>(),
            AddressList_Cc = new List<MailAddress>(),
            AddressList_ReplyTo = new List<MailAddress>(),
            AddressList_ReturnPath = new List<string>(),
            AddressList_OriginalTo = new List<string>(),
            AddressList_DeliveredTo = new List<string>(),
            PlainTextBody = "",
            HtmlBody = "",
            HtmlBodyToPlainText = "",
            AttachmentFileNamesList = new List<string>(),
        };

        try
        {
            using var ms = new MemoryStream(rawMail, writable: false);

            MimeMessage message = MimeMessage.Load(ms);

            // Subject
            try
            {
                meta.Subject = message.Subject ?? "";
            }
            catch { }

            // Message-Id
            try
            {
                meta.MessageId = message.MessageId ?? "";
            }
            catch { }

            // Date header (信頼性は低いが格納する) [YU4CRZ2B]
            try
            {
                meta.DateTime_Header = TryGetDateHeaderDateTime(message);
            }
            catch { }

            // Received header から配信日時を推定
            try
            {
                meta.DateTime_Received = TryGetReceivedDateTime(message) ?? null;
            }
            catch { }

            // From
            try
            {
                MailboxAddress? from = message.From.Mailboxes.FirstOrDefault();
                meta.AddressList_From = TryConvertMailboxAddress(from);
            }
            catch { }

            // To / Cc / ReplyTo
            try
            {
                foreach (var mb in message.To.Mailboxes)
                {
                    MailAddress? addr = TryConvertMailboxAddress(mb);
                    if (addr != null) meta.AddressList_To.Add(addr);
                }
            }
            catch { }

            try
            {
                foreach (var mb in message.Cc.Mailboxes)
                {
                    MailAddress? addr = TryConvertMailboxAddress(mb);
                    if (addr != null) meta.AddressList_Cc.Add(addr);
                }
            }
            catch { }

            try
            {
                foreach (var mb in message.ReplyTo.Mailboxes)
                {
                    MailAddress? addr = TryConvertMailboxAddress(mb);
                    if (addr != null) meta.AddressList_ReplyTo.Add(addr);
                }
            }
            catch { }

            // Return-Path / Delivered-To / X-Original-To (ヘッダから抽出)
            try
            {
                foreach (string v in GetHeaderValues(message, "Return-Path"))
                {
                    if (string.IsNullOrWhiteSpace(v) == false) meta.AddressList_ReturnPath.Add(v.Trim());
                }
            }
            catch { }

            try
            {
                foreach (string v in GetHeaderValues(message, "X-Original-To"))
                {
                    if (string.IsNullOrWhiteSpace(v) == false) meta.AddressList_OriginalTo.Add(v.Trim());
                }
            }
            catch { }

            try
            {
                foreach (string v in GetHeaderValues(message, "Delivered-To"))
                {
                    if (string.IsNullOrWhiteSpace(v) == false) meta.AddressList_DeliveredTo.Add(v.Trim());
                }
            }
            catch { }

            // Body
            try
            {
                meta.PlainTextBody = message.TextBody ?? "";
            }
            catch { }

            try
            {
                meta.HtmlBody = message.HtmlBody ?? "";
            }
            catch { }

            try
            {
                if (string.IsNullOrEmpty(meta.HtmlBody) == false)
                {
                    meta.HtmlBodyToPlainText = ConvertHtmlToPlainText(meta.HtmlBody);
                }
                else
                {
                    meta.HtmlBodyToPlainText = "";
                }
            }
            catch { }

            // Attachments
            try
            {
                foreach (var att in message.Attachments)
                {
                    string? fileName = null;
                    try { fileName = att.ContentDisposition?.FileName; } catch { }
                    if (string.IsNullOrWhiteSpace(fileName))
                    {
                        try { fileName = att.ContentType?.Name; } catch { }
                    }

                    if (string.IsNullOrWhiteSpace(fileName) == false)
                    {
                        meta.AttachmentFileNamesList.Add(fileName!.Trim());
                    }
                }
            }
            catch { }

            // DateTime_Received が不明な場合のフォールバック
            if (meta.DateTime_Received == null)
            {
                meta.DateTime_Received = fetchedNow;
            }
        }
        catch
        {
            // ★ 完全にパースに失敗した場合は、本文はメールバイナリを UTF-8 で無理矢理デコードしたものを入れる [AC579L84]
            meta.PlainTextBody = Encoding.UTF8.GetString(rawMail);
            meta.DateTime_Received = fetchedNow;
        }

        return meta;
    }

    /// <summary>
    /// Date ヘッダから日時を取得します。[YU4CRZ2B]
    /// </summary>
    /// <param name="message">MimeKit のメールオブジェクトです。</param>
    /// <returns>取得できた日時です。取得できない場合は null です。</returns>
    private static DateTimeOffset? TryGetDateHeaderDateTime(MimeMessage message)
    {
        if (message == null) throw new ArgumentNullException(nameof(message));

        // ★ Date ヘッダは様々な「方言」があり得るため、まずは生の Date ヘッダ値を MimeKit の DateUtils でパースする [YU4CRZ2B]
        string? rawDateHeader = GetHeaderValues(message, "Date").FirstOrDefault();
        if (string.IsNullOrWhiteSpace(rawDateHeader) == false)
        {
            if (TryParseRfc822DateTimeBestEffort(rawDateHeader!, out DateTimeOffset dto))
            {
                return dto;
            }
        }

        // ★ MimeKit が解析済みの Date も併用する (生ヘッダが無い/解析不能の場合のフォールバック) [YU4CRZ2B]
        try
        {
            if (message.Date != DateTimeOffset.MinValue)
            {
                return message.Date;
            }
        }
        catch { }

        return null;
    }

    /// <summary>
    /// rfc822 形式の日時文字列を、ベストエフォートでパースします。[YU4CRZ2B][KDXFFA9U]
    /// </summary>
    /// <param name="text">入力文字列です。</param>
    /// <param name="dateTime">出力日時です。</param>
    /// <returns>パースに成功した場合は true です。</returns>
    private static bool TryParseRfc822DateTimeBestEffort(string text, out DateTimeOffset dateTime)
    {
        dateTime = default;

        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        string normalized = NormalizeDateTimeTextForParsing(text);

        if (DateUtils.TryParse(normalized, out dateTime))
        {
            return true;
        }

        // タイムゾーン略称を、数値オフセットに置換/除去して再試行する
        if (TryNormalizeTimeZoneToken(normalized, out string tzNormalized))
        {
            if (DateUtils.TryParse(tzNormalized, out dateTime))
            {
                return true;
            }
        }

        // 最後のフォールバックとして .NET の TryParse を利用する
        if (DateTimeOffset.TryParse(normalized, CultureInfo.InvariantCulture, DateTimeStyles.AllowWhiteSpaces, out dateTime))
        {
            return true;
        }

        if (TryNormalizeTimeZoneToken(normalized, out string tzNormalized2) &&
            DateTimeOffset.TryParse(tzNormalized2, CultureInfo.InvariantCulture, DateTimeStyles.AllowWhiteSpaces, out dateTime))
        {
            return true;
        }

        return false;
    }

    /// <summary>
    /// 日時文字列をパースしやすい形に正規化します。(改行の除去、コメント除去、空白正規化) [YU4CRZ2B][KDXFFA9U]
    /// </summary>
    /// <param name="text">入力文字列です。</param>
    /// <returns>正規化後文字列です。</returns>
    private static string NormalizeDateTimeTextForParsing(string text)
    {
        if (text == null) throw new ArgumentNullException(nameof(text));

        // unfold: CRLF / LF をスペースにする
        string s = text.Replace("\r\n", "\n").Replace("\r", "\n");
        s = s.Replace("\n", " ");

        // コメント ( ... ) を除去
        s = RemoveParenthesizedComments(s);

        // 空白の正規化
        s = NormalizeWhitespaceToSingleSpace(s);

        return s.Trim();
    }

    /// <summary>
    /// () で囲まれたコメントを除去します。(ネスト対応) [YU4CRZ2B][KDXFFA9U]
    /// </summary>
    /// <param name="s">入力文字列です。</param>
    /// <returns>コメント除去後文字列です。</returns>
    private static string RemoveParenthesizedComments(string s)
    {
        if (s == null) throw new ArgumentNullException(nameof(s));

        var sb = new StringBuilder(s.Length);
        int depth = 0;

        foreach (char c in s)
        {
            if (c == '(')
            {
                depth++;
                continue;
            }
            if (c == ')')
            {
                if (depth > 0) depth--;
                continue;
            }

            if (depth == 0)
            {
                sb.Append(c);
            }
        }

        return sb.ToString();
    }

    /// <summary>
    /// 連続空白やタブ等を 1 個の半角スペースに正規化します。
    /// </summary>
    /// <param name="s">入力文字列です。</param>
    /// <returns>正規化後文字列です。</returns>
    private static string NormalizeWhitespaceToSingleSpace(string s)
    {
        if (s == null) throw new ArgumentNullException(nameof(s));

        var sb = new StringBuilder(s.Length);
        bool lastWasSpace = false;

        foreach (char c in s)
        {
            if (char.IsWhiteSpace(c))
            {
                if (lastWasSpace == false)
                {
                    sb.Append(' ');
                    lastWasSpace = true;
                }
            }
            else
            {
                sb.Append(c);
                lastWasSpace = false;
            }
        }

        return sb.ToString();
    }

    /// <summary>
    /// 日時文字列末尾のタイムゾーン略称を、数値オフセットに置換または除去します。[KDXFFA9U][YU4CRZ2B]
    /// </summary>
    /// <param name="src">入力文字列です。</param>
    /// <param name="normalized">出力文字列です。</param>
    /// <returns>置換/除去を行った場合は true です。</returns>
    private static bool TryNormalizeTimeZoneToken(string src, out string normalized)
    {
        if (src == null) throw new ArgumentNullException(nameof(src));

        normalized = src;

        string[] parts = src.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2) return false;

        string last = parts[^1];

        // 末尾が英字のみ (例: JST, PST, GMT) でなければ対象外
        if (last.Length < 2 || last.Length > 6) return false;
        if (last.All(char.IsLetter) == false) return false;

        // すでに直前が数値オフセットなら、末尾略称は無視する (例: +0900 JST)
        if (LooksLikeNumericTimeZoneOffset(parts[^2]))
        {
            normalized = string.Join(' ', parts.Take(parts.Length - 1));
            return true;
        }

        string? offset = last.ToUpperInvariant() switch
        {
            "UT" => "+0000",
            "UTC" => "+0000",
            "GMT" => "+0000",
            "JST" => "+0900",
            "KST" => "+0900",
            "PST" => "-0800",
            "PDT" => "-0700",
            "MST" => "-0700",
            "MDT" => "-0600",
            "CST" => "-0600",
            "CDT" => "-0500",
            "EST" => "-0500",
            "EDT" => "-0400",
            _ => null,
        };

        if (offset == null) return false;

        parts[^1] = offset;
        normalized = string.Join(' ', parts);
        return true;
    }

    /// <summary>
    /// 文字列が数値タイムゾーンオフセット (例: +0900, -0800, +09:00) かどうかを判定します。
    /// </summary>
    /// <param name="s">入力文字列です。</param>
    /// <returns>数値オフセット形式なら true です。</returns>
    private static bool LooksLikeNumericTimeZoneOffset(string s)
    {
        if (s == null) throw new ArgumentNullException(nameof(s));

        s = s.Trim();
        if (s.Length < 5) return false;

        if (s[0] != '+' && s[0] != '-') return false;

        // +HHMM
        if (s.Length == 5)
        {
            return char.IsDigit(s[1]) && char.IsDigit(s[2]) && char.IsDigit(s[3]) && char.IsDigit(s[4]);
        }

        // +HH:MM
        if (s.Length == 6 && s[3] == ':')
        {
            return char.IsDigit(s[1]) && char.IsDigit(s[2]) && char.IsDigit(s[4]) && char.IsDigit(s[5]);
        }

        return false;
    }

    /// <summary>
    /// Received ヘッダから配信日時を推定します。
    /// </summary>
    /// <param name="message">MimeKit のメールオブジェクトです。</param>
    /// <returns>推定できた日時です。推定不能なら null です。</returns>
    private static DateTimeOffset? TryGetReceivedDateTime(MimeMessage message)
    {
        if (message == null) throw new ArgumentNullException(nameof(message));

        // ★ 一般に Received は複数行存在する。最上段 (直近) から順に日時を解釈して、最初に成功したものを採用する。
        var receivedHeaders = message.Headers.Where(x => string.Equals(x.Field, "Received", StringComparison.OrdinalIgnoreCase)).ToList();
        foreach (var h in receivedHeaders)
        {
            string v = h.Value ?? "";

            // ★ Received ヘッダは多様な方言があるため、まずは末尾の ';' 以降を抽出し、rfc822 日時としてベストエフォート解析する [KDXFFA9U]
            if (TryExtractDatePartFromReceivedHeader(v, out string datePart))
            {
                if (TryParseRfc822DateTimeBestEffort(datePart, out DateTimeOffset dto))
                {
                    return dto;
                }
            }
            else
            {
                // ';' が無い場合などのフォールバック
                if (TryParseRfc822DateTimeBestEffort(v, out DateTimeOffset dto2))
                {
                    return dto2;
                }
            }
        }

        return null;
    }

    /// <summary>
    /// Received ヘッダ値から、末尾の日時部分 (通常は最後の ';' 以降) を抽出します。[KDXFFA9U]
    /// </summary>
    /// <param name="receivedHeaderValue">Received ヘッダ値です。</param>
    /// <param name="datePart">抽出された日時部分です。</param>
    /// <returns>抽出できた場合は true です。</returns>
    private static bool TryExtractDatePartFromReceivedHeader(string receivedHeaderValue, out string datePart)
    {
        if (receivedHeaderValue == null) throw new ArgumentNullException(nameof(receivedHeaderValue));

        datePart = "";

        if (string.IsNullOrWhiteSpace(receivedHeaderValue)) return false;

        // unfold + コメント除去してから最後の ';' を探す
        string s = receivedHeaderValue.Replace("\r\n", "\n").Replace("\r", "\n").Replace("\n", " ");
        s = RemoveParenthesizedComments(s);

        int idx = s.LastIndexOf(';');
        if (idx < 0 || idx + 1 >= s.Length) return false;

        datePart = s.Substring(idx + 1).Trim();

        return string.IsNullOrWhiteSpace(datePart) == false;
    }

    /// <summary>
    /// 指定ヘッダ名の値一覧を取得します。
    /// </summary>
    /// <param name="message">MimeKit メッセージです。</param>
    /// <param name="headerName">ヘッダ名です。</param>
    /// <returns>ヘッダ値一覧です。</returns>
    private static IEnumerable<string> GetHeaderValues(MimeMessage message, string headerName)
    {
        if (message == null) throw new ArgumentNullException(nameof(message));
        if (headerName == null) throw new ArgumentNullException(nameof(headerName));

        foreach (var h in message.Headers)
        {
            if (string.Equals(h.Field, headerName, StringComparison.OrdinalIgnoreCase))
            {
                yield return h.Value ?? "";
            }
        }
    }

    /// <summary>
    /// MimeKit の MailboxAddress を System.Net.Mail.MailAddress に変換します。
    /// </summary>
    /// <param name="mb">MailboxAddress です。</param>
    /// <returns>変換後の MailAddress です。失敗した場合は null です。</returns>
    private static MailAddress? TryConvertMailboxAddress(MailboxAddress? mb)
    {
        if (mb == null) return null;

        string address = mb.Address ?? "";
        if (string.IsNullOrWhiteSpace(address)) return null;

        string displayName = mb.Name ?? "";

        try
        {
            if (string.IsNullOrEmpty(displayName))
            {
                return new MailAddress(address);
            }
            else
            {
                return new MailAddress(address, displayName);
            }
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// HTML 文字列を、全文検索に投入可能な程度の平文文字列に変換します。
    /// </summary>
    /// <param name="html">HTML 文字列です。</param>
    /// <returns>平文文字列です。</returns>
    private static string ConvertHtmlToPlainText(string html)
    {
        if (html == null) throw new ArgumentNullException(nameof(html));

        // ★ 最小限の HTML → Text 変換 (タグ除去 + entity デコード)
        string s = html;

        s = s.Replace("\r\n", "\n").Replace("\r", "\n");

        // script/style は削除
        s = RemoveTagBlock(s, "script");
        s = RemoveTagBlock(s, "style");

        // 改行相当タグを改行に
        s = ReplaceIgnoreCase(s, "<br>", "\n");
        s = ReplaceIgnoreCase(s, "<br/>", "\n");
        s = ReplaceIgnoreCase(s, "<br />", "\n");
        s = ReplaceIgnoreCase(s, "</p>", "\n");
        s = ReplaceIgnoreCase(s, "</div>", "\n");
        s = ReplaceIgnoreCase(s, "</tr>", "\n");

        // すべてのタグを除去
        s = StripTags(s);

        // HTML entity をデコード
        s = WebUtility.HtmlDecode(s);

        // 連続空白を整理
        s = NormalizeWhitespace(s);

        return s.Trim();
    }

    /// <summary>
    /// HTML の特定タグブロック (&lt;tag ...&gt;...&lt;/tag&gt;) を大雑把に除去します。
    /// </summary>
    /// <param name="s">入力文字列です。</param>
    /// <param name="tagName">タグ名です。</param>
    /// <returns>除去後文字列です。</returns>
    private static string RemoveTagBlock(string s, string tagName)
    {
        if (s == null) throw new ArgumentNullException(nameof(s));
        if (tagName == null) throw new ArgumentNullException(nameof(tagName));

        string lower = s.ToLowerInvariant();
        string startTag = "<" + tagName.ToLowerInvariant();
        string endTag = "</" + tagName.ToLowerInvariant() + ">";

        int pos = 0;
        while (true)
        {
            int start = lower.IndexOf(startTag, pos, StringComparison.Ordinal);
            if (start < 0) break;
            int end = lower.IndexOf(endTag, start, StringComparison.Ordinal);
            if (end < 0) break;
            end += endTag.Length;
            s = s.Remove(start, end - start);
            lower = s.ToLowerInvariant();
            pos = start;
        }

        return s;
    }

    /// <summary>
    /// 文字列中の HTML タグを単純に除去します。
    /// </summary>
    /// <param name="s">入力文字列です。</param>
    /// <returns>タグ除去後文字列です。</returns>
    private static string StripTags(string s)
    {
        if (s == null) throw new ArgumentNullException(nameof(s));

        var sb = new StringBuilder(s.Length);
        bool inside = false;

        foreach (char c in s)
        {
            if (c == '<')
            {
                inside = true;
                continue;
            }
            if (c == '>')
            {
                inside = false;
                continue;
            }
            if (inside == false)
            {
                sb.Append(c);
            }
        }

        return sb.ToString();
    }

    /// <summary>
    /// 連続空白や不要な空行を整理します。
    /// </summary>
    /// <param name="s">入力文字列です。</param>
    /// <returns>整理後文字列です。</returns>
    private static string NormalizeWhitespace(string s)
    {
        if (s == null) throw new ArgumentNullException(nameof(s));

        s = s.Replace("\r\n", "\n").Replace("\r", "\n");

        var sb = new StringBuilder(s.Length);
        bool lastWasSpace = false;

        foreach (char c in s)
        {
            if (c == '\n')
            {
                sb.Append('\n');
                lastWasSpace = false;
            }
            else if (char.IsWhiteSpace(c))
            {
                if (lastWasSpace == false)
                {
                    sb.Append(' ');
                    lastWasSpace = true;
                }
            }
            else
            {
                sb.Append(c);
                lastWasSpace = false;
            }
        }

        // 連続改行を整理 (3 行以上は 2 行に)
        string tmp = sb.ToString();
        while (tmp.Contains("\n\n\n"))
        {
            tmp = tmp.Replace("\n\n\n", "\n\n");
        }

        return tmp;
    }

    /// <summary>
    /// 大文字小文字を無視して文字列置換をします。(単純実装)
    /// </summary>
    /// <param name="s">対象文字列です。</param>
    /// <param name="oldValue">検索文字列です。</param>
    /// <param name="newValue">置換文字列です。</param>
    /// <returns>置換後文字列です。</returns>
    private static string ReplaceIgnoreCase(string s, string oldValue, string newValue)
    {
        if (s == null) throw new ArgumentNullException(nameof(s));
        if (oldValue == null) throw new ArgumentNullException(nameof(oldValue));
        if (newValue == null) throw new ArgumentNullException(nameof(newValue));

        int idx = 0;
        while (true)
        {
            int pos = s.IndexOf(oldValue, idx, StringComparison.OrdinalIgnoreCase);
            if (pos < 0) break;
            s = s.Remove(pos, oldValue.Length).Insert(pos, newValue);
            idx = pos + newValue.Length;
        }
        return s;
    }

    /// <summary>
    /// メールメタデータの人間向けサマリ文字列を作成します。
    /// </summary>
    /// <param name="prefix">先頭文字列です。</param>
    /// <param name="meta">メタデータです。</param>
    /// <returns>1 行ログ用文字列です。</returns>
    private static string BuildMailMetaSummary(string prefix, MailMetaData meta)
    {
        if (prefix == null) throw new ArgumentNullException(nameof(prefix));
        if (meta == null) throw new ArgumentNullException(nameof(meta));

        string received = meta.DateTime_Received?.ToString("o") ?? "null";
        string from = meta.AddressList_From?.Address ?? "null";
        string to = (meta.AddressList_To != null && meta.AddressList_To.Count >= 1) ? string.Join(",", meta.AddressList_To.Select(x => x.Address)) : "";
        string subject = meta.Subject ?? "";
        string msgid = meta.MessageId ?? "";

        return $"{prefix}: MailSize={meta.MailSize}, DateTime_Received={received}, From={from}, To={to}, Subject={subject}, MessageId={msgid}";
    }

    /// <summary>
    /// アーカイブファイルを書き出します。
    /// </summary>
    /// <param name="config">設定です。</param>
    /// <param name="meta">メタデータです。</param>
    /// <param name="rawMail">生メールです。</param>
    /// <param name="fetchedNow">取得時刻です。</param>
    /// <param name="logger">ロガーです。</param>
    /// <param name="cancel">キャンセル要求です。</param>
    /// <returns>保存先パスです。</returns>
    private static async Task<string> SaveArchiveAsync(ForwardConfig config, MailMetaData meta, byte[] rawMail, DateTimeOffset fetchedNow, ForwardLogger logger, CancellationToken cancel)
    {
        if (config == null) throw new ArgumentNullException(nameof(config));
        if (meta == null) throw new ArgumentNullException(nameof(meta));
        if (rawMail == null) throw new ArgumentNullException(nameof(rawMail));
        if (logger == null) throw new ArgumentNullException(nameof(logger));

        DateTimeOffset dt = meta.DateTime_Received ?? fetchedNow;
        DateTimeOffset local = dt.ToLocalTime();

        string yyMMdd = local.ToString("yyMMdd", CultureInfo.InvariantCulture);
        string hhmmss = local.ToString("HHmmss", CultureInfo.InvariantCulture);

        string metaJsonBody = JsonConvert.SerializeObject(meta, LibCommon.CreateStandardJsonSerializerSettings());
        metaJsonBody = metaJsonBody.Replace("\r\n", "\n").Replace("\r", "\n").TrimEnd('\n');

        string sha1Hex = ComputeSha1Hex(Encoding.UTF8.GetBytes(metaJsonBody));

        string from64 = BuildFrom64(meta.AddressList_From);

        string fileName = $"{yyMMdd}_{hhmmss}_{sha1Hex}_{from64}.txt";
        string dir = Path.Combine(config.Generic.ArchiveDir, yyMMdd);
        string fullPath = Path.Combine(dir, fileName);

        Directory.CreateDirectory(dir);

        byte[] bom = new byte[] { 0xEF, 0xBB, 0xBF };
        byte[] sep = Encoding.ASCII.GetBytes("===================================================================\n");
        byte[] lf2 = Encoding.ASCII.GetBytes("\n\n");

        using (var fs = new FileStream(fullPath, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            await fs.WriteAsync(bom, 0, bom.Length, cancel).ConfigureAwait(false);
            await fs.WriteAsync(lf2, 0, lf2.Length, cancel).ConfigureAwait(false);

            byte[] metaBytes = Encoding.UTF8.GetBytes(metaJsonBody);
            await fs.WriteAsync(metaBytes, 0, metaBytes.Length, cancel).ConfigureAwait(false);

            await fs.WriteAsync(lf2, 0, lf2.Length, cancel).ConfigureAwait(false);
            await fs.WriteAsync(sep, 0, sep.Length, cancel).ConfigureAwait(false);

            await fs.WriteAsync(rawMail, 0, rawMail.Length, cancel).ConfigureAwait(false);
        }

        long size = new FileInfo(fullPath).Length;
        logger.Info($"Archive saved: {fullPath} (size={size})");

        return fullPath;
    }

    /// <summary>
    /// SHA1 ハッシュ値 (小文字 16 進数) を計算します。
    /// </summary>
    /// <param name="data">入力データです。</param>
    /// <returns>小文字 16 進数文字列です。</returns>
    private static string ComputeSha1Hex(byte[] data)
    {
        if (data == null) throw new ArgumentNullException(nameof(data));

        using var sha1 = SHA1.Create();
        byte[] hash = sha1.ComputeHash(data);
        var sb = new StringBuilder(hash.Length * 2);
        foreach (byte b in hash)
        {
            sb.Append(b.ToString("x2", CultureInfo.InvariantCulture));
        }
        return sb.ToString();
    }

    /// <summary>
    /// FROM64 文字列を生成します。
    /// </summary>
    /// <param name="from">From メールアドレスです。</param>
    /// <returns>FROM64 文字列です。</returns>
    private static string BuildFrom64(MailAddress? from)
    {
        string src = from?.Address ?? "unknown";

        var sb = new StringBuilder(src.Length);
        foreach (char c in src)
        {
            if ((c >= 'a' && c <= 'z') ||
                (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') ||
                c == '@' || c == '+' || c == '-' || c == '_' || c == '.')
            {
                sb.Append(c);
            }
            else
            {
                sb.Append('_');
            }
        }

        string s = sb.ToString();
        if (s.Length > 64) s = s.Substring(0, 64);

        if (string.IsNullOrWhiteSpace(s)) s = "unknown";

        return s;
    }

    /// <summary>
    /// Gmail 用アクセストークンを取得します。必要なら refresh を実施します。
    /// </summary>
    /// <param name="config">設定です。</param>
    /// <param name="logger">ロガーです。</param>
    /// <param name="cancel">キャンセル要求です。</param>
    /// <returns>アクセストークンです。</returns>
    private static async Task<string> EnsureGmailAccessTokenAsync(ForwardConfig config, ForwardLogger logger, CancellationToken cancel)
    {
        if (config == null) throw new ArgumentNullException(nameof(config));
        if (logger == null) throw new ArgumentNullException(nameof(logger));

        FeatureGetToken.GMailOAuthTokenJsonData token = await LibCommon.ReadSingleJsonFileAsync<FeatureGetToken.GMailOAuthTokenJsonData>(config.Gmail.TokenJsonPath, cancel).ConfigureAwait(false);

        DateTimeOffset now = DateTimeOffset.Now;

        if ((now - token.LastRefreshDt).TotalSeconds >= config.Gmail.GmailTokenRefreshIntervalSecs)
        {
            if (string.IsNullOrWhiteSpace(token.UserRefreshToken))
            {
                throw new Exception("APPERROR: token_json does not contain refresh token (UserRefreshToken). Re-run gettoken.");
            }

            string newAccessToken = await RefreshGmailAccessTokenAsync(config, token, cancel).ConfigureAwait(false);

            token.UserAccessToken = newAccessToken;
            token.LastRefreshDt = now;

            await LibCommon.WriteSingleJsonFileByTempAsync(config.Gmail.TokenJsonPath, token, cancel).ConfigureAwait(false);

            logger.Info("Gmail access token refreshed and saved.");
        }

        if (string.IsNullOrWhiteSpace(token.UserAccessToken))
        {
            throw new Exception("APPERROR: token_json does not contain access token (UserAccessToken). Re-run gettoken.");
        }

        return token.UserAccessToken;
    }

    /// <summary>
    /// refresh_token を用いて Gmail のアクセストークンを更新します。
    /// </summary>
    /// <param name="config">設定です。</param>
    /// <param name="token">現在のトークン情報です。</param>
    /// <param name="cancel">キャンセル要求です。</param>
    /// <returns>新しいアクセストークンです。</returns>
    private static async Task<string> RefreshGmailAccessTokenAsync(ForwardConfig config, FeatureGetToken.GMailOAuthTokenJsonData token, CancellationToken cancel)
    {
        if (config == null) throw new ArgumentNullException(nameof(config));
        if (token == null) throw new ArgumentNullException(nameof(token));

        const string tokenEndpoint = "https://oauth2.googleapis.com/token";

        using HttpClient httpClient = CreateHttpClientForGmail(config);

        using var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = token.AppClientId,
            ["client_secret"] = token.AppClientSecret,
            ["refresh_token"] = token.UserRefreshToken,
            ["grant_type"] = "refresh_token",
        });

        using HttpResponseMessage resp = await httpClient.PostAsync(tokenEndpoint, content, cancel).ConfigureAwait(false);
        string body = await resp.Content.ReadAsStringAsync(cancel).ConfigureAwait(false);

        if (resp.IsSuccessStatusCode == false)
        {
            throw new Exception($"APPERROR: OAuth refresh token endpoint returned {(int)resp.StatusCode} {resp.ReasonPhrase}. Body: {body}");
        }

        try
        {
            var json = Newtonsoft.Json.Linq.JObject.Parse(body);
            string? accessToken = json.Value<string>("access_token");
            if (string.IsNullOrWhiteSpace(accessToken))
            {
                throw new Exception($"APPERROR: Refresh response does not contain access_token. Body: {body}");
            }
            return accessToken;
        }
        catch (Exception ex)
        {
            throw new Exception(LibCommon.AppendExceptionDetail($"APPERROR: Failed to parse refresh token endpoint JSON response. Body: {body}", ex), ex);
        }
    }

    /// <summary>
    /// Gmail API の users.messages.import を呼び出します。
    /// </summary>
    /// <param name="config">設定です。</param>
    /// <param name="accessToken">アクセストークンです。</param>
    /// <param name="rawMail">メールの生データです。</param>
    /// <param name="cancel">キャンセル要求です。</param>
    private static async Task GmailApiImportAsync(ForwardConfig config, string accessToken, byte[] rawMail, CancellationToken cancel)
    {
        if (config == null) throw new ArgumentNullException(nameof(config));
        if (accessToken == null) throw new ArgumentNullException(nameof(accessToken));
        if (rawMail == null) throw new ArgumentNullException(nameof(rawMail));

        // ★ Gmail API users.messages.import は multipart upload を用いて、生メールデータを base64 変換せずに送信する
        //    これにより、サイズ増大 (base64 の 4/3) を回避し、(a) の生データをそのまま送れる。
        string metaJson = JsonConvert.SerializeObject(new { labelIds = new[] { "INBOX", "UNREAD" } }, LibCommon.CreateStandardJsonSerializerSettings());
        metaJson = metaJson.Replace("\r\n", "\n").Replace("\r", "\n");

        using HttpClient httpClient = CreateHttpClientForGmail(config);

        string url = "https://gmail.googleapis.com/upload/gmail/v1/users/me/messages/import?uploadType=multipart";

        for (int attempt = 1; attempt <= config.Gmail.TcpRetryAttempts; attempt++)
        {
            cancel.ThrowIfCancellationRequested();
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Post, url);
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

                using var multipart = new MultipartContent("related");

                // part 1: JSON metadata
                var jsonPart = new StringContent(metaJson, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false), "application/json");
                multipart.Add(jsonPart);

                // part 2: raw message
                var mailPart = new ByteArrayContent(rawMail);
                mailPart.Headers.ContentType = new MediaTypeHeaderValue("message/rfc822");
                multipart.Add(mailPart);

                req.Content = multipart;

                using HttpResponseMessage resp = await httpClient.SendAsync(req, cancel).ConfigureAwait(false);
                string body = await resp.Content.ReadAsStringAsync(cancel).ConfigureAwait(false);

                if (resp.IsSuccessStatusCode)
                {
                    return;
                }

                // 4xx は即失敗 (リトライしても意味が薄い) / 5xx はリトライ
                if ((int)resp.StatusCode >= 500 && attempt < config.Gmail.TcpRetryAttempts)
                {
                    await Task.Delay(500, cancel).ConfigureAwait(false);
                    continue;
                }

                throw new Exception($"APPERROR: Gmail API users.messages.import returned {(int)resp.StatusCode} {resp.ReasonPhrase}. Body: {body}");
            }
            catch (HttpRequestException) when (attempt < config.Gmail.TcpRetryAttempts)
            {
                await Task.Delay(500, cancel).ConfigureAwait(false);
                continue;
            }
        }
    }

    /// <summary>
    /// Gmail 通信用の HttpClient を生成します。
    /// </summary>
    /// <param name="config">設定です。</param>
    /// <returns>HttpClient です。</returns>
    private static HttpClient CreateHttpClientForGmail(ForwardConfig config)
    {
        if (config == null) throw new ArgumentNullException(nameof(config));

        var handler = new SocketsHttpHandler
        {
            ConnectTimeout = TimeSpan.FromSeconds(config.Gmail.TcpConnectTimeoutSecs),
        };

        if (config.Gmail.SslVerifyServerCert == false)
        {
            handler.SslOptions = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = (sender, cert, chain, errors) => true,
            };
        }

        var client = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(Math.Max(1, config.Gmail.TcpSendTimeoutSecs + config.Gmail.TcpRecvTimeoutSecs)),
        };

        return client;
    }

    /// <summary>
    /// forward 用設定ファイルを読み込みます。[A44FBNFX]
    /// </summary>
    /// <param name="configPath">設定ファイルパスです。</param>
    /// <param name="cancel">キャンセル要求です。</param>
    /// <returns>設定データです。</returns>
    private static async Task<ForwardConfig> LoadConfigAsync(string configPath, CancellationToken cancel)
    {
        if (string.IsNullOrWhiteSpace(configPath)) throw new ArgumentException("APPERROR: configPath is empty.", nameof(configPath));

        string fullPath = Path.GetFullPath(configPath);
        if (File.Exists(fullPath) == false)
        {
            throw new Exception($"APPERROR: Config file not found: {fullPath}");
        }

        string configDir = Path.GetDirectoryName(fullPath) ?? Directory.GetCurrentDirectory();

        string tomlText = await File.ReadAllTextAsync(fullPath, cancel).ConfigureAwait(false);

        TomlTable model;
        try
        {
            object? obj = Toml.ToModel(tomlText);
            model = obj as TomlTable ?? throw new Exception("APPERROR: TOML root is not a table.");
        }
        catch (Exception ex)
        {
            throw new Exception(LibCommon.AppendExceptionDetail("APPERROR: Failed to parse TOML config file.", ex), ex);
        }

        var cfg = new ForwardConfig
        {
            ConfigFilePath = fullPath,
            ConfigDir = configDir,
        };

        // generic
        cfg.Generic = new GenericConfig
        {
            ArchiveDir = ResolveConfigPath(configDir, GetRequiredString(model, "generic", "archive_dir")),
            LogDir = ResolveConfigPath(configDir, GetRequiredString(model, "generic", "log_dir")),
        };

        // pop3
        cfg.Pop3 = new Pop3Config
        {
            Hostname = GetRequiredString(model, "pop3", "hostname"),
            Port = GetRequiredInt(model, "pop3", "port", 1, 65535),
            SslMode = ParseRequiredSslMode(GetRequiredString(model, "pop3", "ssl_mode")),
            SslVerifyServerCert = GetRequiredBool(model, "pop3", "ssl_verify_server_cert"),
            SslTrustedStaticHashList = ParseSslTrustedStaticHashList(GetOptionalString(model, "pop3", "ssl_trusted_static_hash_list")),
            Username = GetRequiredString(model, "pop3", "username"),
            Password = GetRequiredString(model, "pop3", "password"),
            TcpRetryAttempts = GetRequiredInt(model, "pop3", "tcp_retry_attempts", 1, 100),
            TcpConnectTimeoutSecs = GetRequiredInt(model, "pop3", "tcp_connect_timeout_secs", 1, 3600),
            TcpSendTimeoutSecs = GetRequiredInt(model, "pop3", "tcp_send_timeout_secs", 1, 3600),
            TcpRecvTimeoutSecs = GetRequiredInt(model, "pop3", "tcp_recv_timeout_secs", 1, 3600),
            MaxBatchMailsPerLogin = GetRequiredInt(model, "pop3", "max_batch_mails_per_login", 1, 1000000),
        };

        // gmail
        cfg.Gmail = new GmailConfig
        {
            TokenJsonPath = ResolveConfigPath(configDir, GetRequiredString(model, "gmail", "token_json")),
            SslVerifyServerCert = GetRequiredBool(model, "gmail", "ssl_verify_server_cert"),
            TcpRetryAttempts = GetRequiredInt(model, "gmail", "tcp_retry_attempts", 1, 100),
            TcpConnectTimeoutSecs = GetRequiredInt(model, "gmail", "tcp_connect_timeout_secs", 1, 3600),
            TcpSendTimeoutSecs = GetRequiredInt(model, "gmail", "tcp_send_timeout_secs", 1, 3600),
            TcpRecvTimeoutSecs = GetRequiredInt(model, "gmail", "tcp_recv_timeout_secs", 1, 3600),
            GmailTokenRefreshIntervalSecs = GetRequiredInt(model, "gmail", "gmail_token_refresh_interval_secs", 1, 3600 * 24),
            GmailMaxMailSize = GetRequiredInt(model, "gmail", "gmail_max_mail_size", 1, 1000_000_000),
        };

        return cfg;
    }

    /// <summary>
    /// ssl_mode の値をパースします。
    /// </summary>
    /// <param name="s">入力文字列です。</param>
    /// <returns>パース結果です。</returns>
    private static Pop3SslMode ParseRequiredSslMode(string s)
    {
        if (string.IsNullOrWhiteSpace(s)) throw new Exception("APPERROR: pop3.ssl_mode is empty.");

        return s.Trim().ToLowerInvariant() switch
        {
            "none" => Pop3SslMode.None,
            "starttls" => Pop3SslMode.StartTls,
            "full" => Pop3SslMode.Full,
            _ => throw new Exception("APPERROR: pop3.ssl_mode must be one of: none, starttls, full."),
        };
    }

    /// <summary>
    /// ssl_trusted_static_hash_list をパースします。[A44FBNFX]
    /// </summary>
    /// <param name="src">設定値文字列です。</param>
    /// <returns>正規化済みハッシュ文字列のセットです。</returns>
    private static HashSet<string> ParseSslTrustedStaticHashList(string src)
    {
        var set = new HashSet<string>(StringComparer.Ordinal);

        if (string.IsNullOrWhiteSpace(src))
        {
            return set;
        }

        string[] tokens = src.Split(new[] { ';', ',' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (string token in tokens)
        {
            string s = NormalizeHexString(token);
            if (string.IsNullOrEmpty(s))
            {
                continue;
            }

            // SHA1: 40, SHA192: 48, SHA256: 64, SHA384: 96, SHA512: 128 (いずれか) [A44FBNFX]
            if (s.Length != 40 && s.Length != 48 && s.Length != 64 && s.Length != 96 && s.Length != 128)
            {
                throw new Exception($"APPERROR: pop3.ssl_trusted_static_hash_list contains invalid hash length: {s.Length}");
            }

            if (IsAllHexString(s) == false)
            {
                throw new Exception("APPERROR: pop3.ssl_trusted_static_hash_list contains non-hex character.");
            }

            set.Add(s);
        }

        return set;
    }

    /// <summary>
    /// 16 進数文字列を正規化します。(空白、':'、'-' を除去し、小文字化) [A44FBNFX]
    /// </summary>
    /// <param name="src">入力文字列です。</param>
    /// <returns>正規化後の文字列です。</returns>
    private static string NormalizeHexString(string src)
    {
        if (src == null) throw new ArgumentNullException(nameof(src));

        var sb = new StringBuilder(src.Length);
        foreach (char c in src)
        {
            if (char.IsWhiteSpace(c) || c == ':' || c == '-')
            {
                continue;
            }

            sb.Append(char.ToLowerInvariant(c));
        }

        return sb.ToString();
    }

    /// <summary>
    /// 文字列が 0-9a-f のみで構成されているか確認します。
    /// </summary>
    /// <param name="s">入力文字列です。</param>
    /// <returns>すべて 16 進数文字なら true です。</returns>
    private static bool IsAllHexString(string s)
    {
        if (s == null) throw new ArgumentNullException(nameof(s));

        foreach (char c in s)
        {
            bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
            if (ok == false) return false;
        }

        return true;
    }

    /// <summary>
    /// 設定ファイルディレクトリを基準にパスを解決します。
    /// </summary>
    /// <param name="configDir">設定ファイルの存在ディレクトリです。</param>
    /// <param name="path">入力パスです。</param>
    /// <returns>フルパスです。</returns>
    private static string ResolveConfigPath(string configDir, string path)
    {
        if (configDir == null) throw new ArgumentNullException(nameof(configDir));
        if (path == null) throw new ArgumentNullException(nameof(path));

        if (Path.IsPathRooted(path))
        {
            return Path.GetFullPath(path);
        }
        else
        {
            return Path.GetFullPath(Path.Combine(configDir, path));
        }
    }

    /// <summary>
    /// TOML の必須文字列フィールドを取得します。
    /// </summary>
    /// <param name="root">ルートテーブルです。</param>
    /// <param name="tableName">テーブル名です。</param>
    /// <param name="key">キー名です。</param>
    /// <returns>文字列値です。</returns>
    private static string GetRequiredString(TomlTable root, string tableName, string key)
    {
        if (root == null) throw new ArgumentNullException(nameof(root));
        if (tableName == null) throw new ArgumentNullException(nameof(tableName));
        if (key == null) throw new ArgumentNullException(nameof(key));

        if (root.TryGetValue(tableName, out object? tableObj) == false || tableObj is TomlTable table == false)
        {
            throw new Exception($"APPERROR: Missing TOML table [{tableName}].");
        }

        if (table.TryGetValue(key, out object? valueObj) == false || valueObj == null)
        {
            throw new Exception($"APPERROR: Missing TOML value: {tableName}.{key}");
        }

        if (valueObj is string s)
        {
            if (string.IsNullOrWhiteSpace(s))
            {
                throw new Exception($"APPERROR: TOML value is empty: {tableName}.{key}");
            }
            return s;
        }

        throw new Exception($"APPERROR: TOML value type must be string: {tableName}.{key}");
    }

    /// <summary>
    /// TOML の任意文字列フィールドを取得します。(無い場合は "" を返します)
    /// </summary>
    /// <param name="root">ルートテーブルです。</param>
    /// <param name="tableName">テーブル名です。</param>
    /// <param name="key">キー名です。</param>
    /// <returns>文字列値です。</returns>
    private static string GetOptionalString(TomlTable root, string tableName, string key)
    {
        if (root == null) throw new ArgumentNullException(nameof(root));
        if (tableName == null) throw new ArgumentNullException(nameof(tableName));
        if (key == null) throw new ArgumentNullException(nameof(key));

        if (root.TryGetValue(tableName, out object? tableObj) == false || tableObj is TomlTable table == false)
        {
            return "";
        }

        if (table.TryGetValue(key, out object? valueObj) == false || valueObj == null)
        {
            return "";
        }

        if (valueObj is string s)
        {
            return s;
        }

        throw new Exception($"APPERROR: TOML value type must be string: {tableName}.{key}");
    }

    /// <summary>
    /// TOML の必須 int フィールドを取得します。
    /// </summary>
    /// <param name="root">ルートテーブルです。</param>
    /// <param name="tableName">テーブル名です。</param>
    /// <param name="key">キー名です。</param>
    /// <param name="min">最小値です。</param>
    /// <param name="max">最大値です。</param>
    /// <returns>int 値です。</returns>
    private static int GetRequiredInt(TomlTable root, string tableName, string key, int min, int max)
    {
        if (root == null) throw new ArgumentNullException(nameof(root));
        if (tableName == null) throw new ArgumentNullException(nameof(tableName));
        if (key == null) throw new ArgumentNullException(nameof(key));

        if (root.TryGetValue(tableName, out object? tableObj) == false || tableObj is TomlTable table == false)
        {
            throw new Exception($"APPERROR: Missing TOML table [{tableName}].");
        }

        if (table.TryGetValue(key, out object? valueObj) == false || valueObj == null)
        {
            throw new Exception($"APPERROR: Missing TOML value: {tableName}.{key}");
        }

        long n;
        if (valueObj is long l)
        {
            n = l;
        }
        else if (valueObj is int i)
        {
            n = i;
        }
        else
        {
            throw new Exception($"APPERROR: TOML value type must be integer: {tableName}.{key}");
        }

        if (n < min || n > max)
        {
            throw new Exception($"APPERROR: TOML integer out of range ({min}..{max}): {tableName}.{key} = {n}");
        }

        return (int)n;
    }

    /// <summary>
    /// TOML の必須 bool フィールドを取得します。
    /// </summary>
    /// <param name="root">ルートテーブルです。</param>
    /// <param name="tableName">テーブル名です。</param>
    /// <param name="key">キー名です。</param>
    /// <returns>bool 値です。</returns>
    private static bool GetRequiredBool(TomlTable root, string tableName, string key)
    {
        if (root == null) throw new ArgumentNullException(nameof(root));
        if (tableName == null) throw new ArgumentNullException(nameof(tableName));
        if (key == null) throw new ArgumentNullException(nameof(key));

        if (root.TryGetValue(tableName, out object? tableObj) == false || tableObj is TomlTable table == false)
        {
            throw new Exception($"APPERROR: Missing TOML table [{tableName}].");
        }

        if (table.TryGetValue(key, out object? valueObj) == false || valueObj == null)
        {
            throw new Exception($"APPERROR: Missing TOML value: {tableName}.{key}");
        }

        if (valueObj is bool b)
        {
            return b;
        }

        throw new Exception($"APPERROR: TOML value type must be bool: {tableName}.{key}");
    }

    /// <summary>
    /// forward 設定データです。[A44FBNFX]
    /// </summary>
    private sealed class ForwardConfig
    {
        /// <summary>
        /// 設定ファイルのフルパスです。
        /// </summary>
        public string ConfigFilePath = "";

        /// <summary>
        /// 設定ファイルの存在ディレクトリです。
        /// </summary>
        public string ConfigDir = "";

        /// <summary>
        /// generic セクションです。
        /// </summary>
        public GenericConfig Generic = new GenericConfig();

        /// <summary>
        /// pop3 セクションです。
        /// </summary>
        public Pop3Config Pop3 = new Pop3Config();

        /// <summary>
        /// gmail セクションです。
        /// </summary>
        public GmailConfig Gmail = new GmailConfig();
    }

    /// <summary>
    /// generic 設定です。
    /// </summary>
    private sealed class GenericConfig
    {
        /// <summary>
        /// アーカイブディレクトリです。(フルパス)
        /// </summary>
        public string ArchiveDir = "";

        /// <summary>
        /// ログディレクトリです。(フルパス)
        /// </summary>
        public string LogDir = "";
    }

    /// <summary>
    /// pop3 設定です。
    /// </summary>
    private sealed class Pop3Config
    {
        /// <summary>
        /// POP3 サーバーホスト名です。
        /// </summary>
        public string Hostname = "";

        /// <summary>
        /// POP3 サーバーポート番号です。
        /// </summary>
        public int Port;

        /// <summary>
        /// SSL モードです。
        /// </summary>
        public Pop3SslMode SslMode;

        /// <summary>
        /// サーバー証明書の検証を行うかどうかです。
        /// </summary>
        public bool SslVerifyServerCert;

        /// <summary>
        /// サーバー証明書を静的ハッシュ値で信頼するためのリストです。[A44FBNFX]
        /// </summary>
        public HashSet<string> SslTrustedStaticHashList = new HashSet<string>(StringComparer.Ordinal);

        /// <summary>
        /// POP3 認証ユーザー名です。
        /// </summary>
        public string Username = "";

        /// <summary>
        /// POP3 認証パスワードです。
        /// </summary>
        public string Password = "";

        /// <summary>
        /// TCP 接続リトライ回数です。
        /// </summary>
        public int TcpRetryAttempts;

        /// <summary>
        /// TCP 接続タイムアウト秒数です。
        /// </summary>
        public int TcpConnectTimeoutSecs;

        /// <summary>
        /// TCP 送信タイムアウト秒数です。
        /// </summary>
        public int TcpSendTimeoutSecs;

        /// <summary>
        /// TCP 受信タイムアウト秒数です。
        /// </summary>
        public int TcpRecvTimeoutSecs;

        /// <summary>
        /// 1 回の POP3 ログインごとに回す最大メール数です。
        /// </summary>
        public int MaxBatchMailsPerLogin;
    }

    /// <summary>
    /// POP3 の SSL 使用モードです。
    /// </summary>
    private enum Pop3SslMode
    {
        /// <summary>
        /// SSL 未使用です。
        /// </summary>
        None,

        /// <summary>
        /// STLS (STARTTLS) を使用します。
        /// </summary>
        StartTls,

        /// <summary>
        /// 接続直後から SSL でラップします。
        /// </summary>
        Full,
    }

    /// <summary>
    /// gmail 設定です。
    /// </summary>
    private sealed class GmailConfig
    {
        /// <summary>
        /// gettoken モードで作成された token JSON ファイルパスです。(フルパス)
        /// </summary>
        public string TokenJsonPath = "";

        /// <summary>
        /// サーバー証明書の検証を行うかどうかです。
        /// </summary>
        public bool SslVerifyServerCert;

        /// <summary>
        /// TCP 接続リトライ回数です。
        /// </summary>
        public int TcpRetryAttempts;

        /// <summary>
        /// TCP 接続タイムアウト秒数です。
        /// </summary>
        public int TcpConnectTimeoutSecs;

        /// <summary>
        /// TCP 送信タイムアウト秒数です。
        /// </summary>
        public int TcpSendTimeoutSecs;

        /// <summary>
        /// TCP 受信タイムアウト秒数です。
        /// </summary>
        public int TcpRecvTimeoutSecs;

        /// <summary>
        /// トークン更新間隔秒数です。
        /// </summary>
        public int GmailTokenRefreshIntervalSecs;

        /// <summary>
        /// 最大メールバイト数です。
        /// </summary>
        public int GmailMaxMailSize;
    }

    /// <summary>
    /// forward モードのログ出力実装です。[Y5CRNZA3]
    /// </summary>
    private sealed class ForwardLogger
    {
        private readonly string _logDir;

        /// <summary>
        /// コンストラクタです。
        /// </summary>
        /// <param name="logDir">ログ保存先ディレクトリです。</param>
        public ForwardLogger(string logDir)
        {
            if (string.IsNullOrWhiteSpace(logDir)) throw new ArgumentException("APPERROR: logDir is empty.", nameof(logDir));
            _logDir = logDir;
        }

        /// <summary>
        /// Info ログを出力します。
        /// </summary>
        /// <param name="message">メッセージです。</param>
        public void Info(string message)
        {
            Write("Info", message, isError: false);
        }

        /// <summary>
        /// Error ログを出力します。
        /// </summary>
        /// <param name="message">メッセージです。</param>
        public void Error(string message)
        {
            Write("Error", message, isError: true);
        }

        /// <summary>
        /// Error を標準エラー出力のみに出力します。(ログ保存なし)
        /// </summary>
        /// <param name="message">メッセージです。</param>
        public static void WriteErrorToConsoleOnly(string message)
        {
            string line = BuildLogLine("Error", message);
            try { Console.Error.WriteLine(line); } catch { }
        }

        private void Write(string type, string message, bool isError)
        {
            string line = BuildLogLine(type, message);

            // まずコンソールへ (仕様: Info は stdout, Error は stderr)
            try
            {
                if (isError) Console.Error.WriteLine(line);
                else Console.WriteLine(line);
            }
            catch { }

            // ファイル保存
            try
            {
                Directory.CreateDirectory(_logDir);

                string fileName = DateTimeOffset.Now.ToLocalTime().ToString("yyMMdd", CultureInfo.InvariantCulture) + ".log";
                string path = Path.Combine(_logDir, fileName);

                // 改行は LF のみで保存
                File.AppendAllText(path, line + "\n", new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            }
            catch (Exception ex)
            {
                // 仕様: ログ保存に失敗した場合は、その旨を標準エラー出力に出して続行
                try
                {
                    Console.Error.WriteLine(BuildLogLine("Error", $"LOGSAVEFAIL: {ex.Message}"));
                }
                catch { }
            }
        }

        private static string BuildLogLine(string type, string message)
        {
            if (type == null) type = "Info";
            if (message == null) message = "";

            DateTimeOffset now = DateTimeOffset.Now;
            string ts = now.ToString("yyyy/MM/dd HH:mm:ss.fff zzz", CultureInfo.InvariantCulture);

            string body = message.Replace("\r\n", " / ").Replace("\r", " / ").Replace("\n", " / ");

            return $"{ts} [{type}] {body}";
        }
    }

    /// <summary>
    /// POP3 クライアントの最小実装です。(外部 NuGet ライブラリ不使用) [AC579L84]
    /// </summary>
    private sealed class Pop3Client : IAsyncDisposable, IDisposable
    {
        private readonly Pop3Config _config;
        private TcpClient? _tcp;
        private Stream? _stream;
        private StreamReader? _reader;
        private StreamWriter? _writer;
        private int _disposed;

        private Pop3Client(Pop3Config config)
        {
            _config = config;
        }

        /// <summary>
        /// 接続してログインします。
        /// </summary>
        /// <param name="config">POP3 設定です。</param>
        /// <param name="logger">ロガーです。</param>
        /// <param name="cancel">キャンセル要求です。</param>
        /// <returns>接続済みクライアントです。</returns>
        public static async Task<Pop3Client> ConnectAndLoginAsync(Pop3Config config, ForwardLogger logger, CancellationToken cancel)
        {
            if (config == null) throw new ArgumentNullException(nameof(config));
            if (logger == null) throw new ArgumentNullException(nameof(logger));

            var c = new Pop3Client(config);

            try
            {
                await c.ConnectAsync(cancel).ConfigureAwait(false);
                await c.LoginAsync(logger, cancel).ConfigureAwait(false);
                return c;
            }
            catch
            {
                await c.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }

        /// <summary>
        /// STAT を取得します。
        /// </summary>
        /// <param name="cancel">キャンセル要求です。</param>
        /// <returns>(件数, 合計サイズ) です。</returns>
        public async Task<(int Count, int TotalSize)> StatAsync(CancellationToken cancel)
        {
            string resp = await SendCommandGetSingleLineResponseAsync("STAT", cancel).ConfigureAwait(false);
            // +OK <count> <size>
            string[] parts = resp.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 3 &&
                int.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out int count) &&
                int.TryParse(parts[2], NumberStyles.Integer, CultureInfo.InvariantCulture, out int size))
            {
                return (count, size);
            }

            throw new Exception($"APPERROR: Invalid STAT response: {resp}");
        }

        /// <summary>
        /// メッセージを 1 件取得します。(dot-stuffing 解除済み)
        /// </summary>
        /// <param name="messageNo">メッセージ番号です。(1..)</param>
        /// <param name="cancel">キャンセル要求です。</param>
        /// <returns>生メールバイト列です。</returns>
        public async Task<byte[]> RetrieveMessageAsync(int messageNo, CancellationToken cancel)
        {
            if (messageNo <= 0) throw new ArgumentOutOfRangeException(nameof(messageNo));

            await SendCommandAsync($"RETR {messageNo}", cancel).ConfigureAwait(false);
            string first = await ReadLineAsync(cancel).ConfigureAwait(false);
            EnsureOk(first);

            using var ms = new MemoryStream();
            byte[] crlf = Encoding.ASCII.GetBytes("\r\n");

            while (true)
            {
                string line = await ReadLineAsync(cancel).ConfigureAwait(false);
                if (line == ".")
                {
                    break;
                }

                if (line.StartsWith("..", StringComparison.Ordinal))
                {
                    line = line.Substring(1);
                }

                byte[] bytes = Encoding.Latin1.GetBytes(line);
                ms.Write(bytes, 0, bytes.Length);
                ms.Write(crlf, 0, crlf.Length);
            }

            return ms.ToArray();
        }

        /// <summary>
        /// メッセージを削除マークします。(QUIT で実削除される)
        /// </summary>
        /// <param name="messageNo">メッセージ番号です。(1..)</param>
        /// <param name="cancel">キャンセル要求です。</param>
        public async Task DeleteMessageAsync(int messageNo, CancellationToken cancel)
        {
            if (messageNo <= 0) throw new ArgumentOutOfRangeException(nameof(messageNo));

            string resp = await SendCommandGetSingleLineResponseAsync($"DELE {messageNo}", cancel).ConfigureAwait(false);
            EnsureOk(resp);
        }

        /// <summary>
        /// QUIT を送信します。
        /// </summary>
        /// <param name="cancel">キャンセル要求です。</param>
        public async Task QuitAsync(CancellationToken cancel)
        {
            try
            {
                string resp = await SendCommandGetSingleLineResponseAsync("QUIT", cancel).ConfigureAwait(false);
                EnsureOk(resp);
            }
            catch
            {
                // ここはベストエフォート
            }
        }

        /// <summary>
        /// IDisposable.Dispose() です。
        /// </summary>
        public void Dispose()
        {
            this.Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// IAsyncDisposable.DisposeAsync() です。
        /// </summary>
        /// <returns>完了タスクです。</returns>
        public async ValueTask DisposeAsync()
        {
            if (Interlocked.CompareExchange(ref _disposed, 1, 0) != 0) return;
            await DisposeInternalAsync().ConfigureAwait(false);
        }

        /// <summary>
        /// Dispose 実装本体です。
        /// </summary>
        /// <param name="disposing">disposing フラグです。</param>
        private void Dispose(bool disposing)
        {
            if (disposing == false) return;
            if (Interlocked.CompareExchange(ref _disposed, 1, 0) != 0) return;
            DisposeInternalAsync().GetAwaiter().GetResult();
        }

        private async Task DisposeInternalAsync()
        {
            try
            {
                if (_stream != null)
                {
                    try
                    {
                        // 可能なら QUIT を送る
                        await QuitAsync(CancellationToken.None).ConfigureAwait(false);
                    }
                    catch { }
                }
            }
            catch { }

            try { _writer?.Dispose(); } catch { }
            try { _reader?.Dispose(); } catch { }
            try { _stream?.Dispose(); } catch { }
            try { _tcp?.Close(); } catch { }
            try { _tcp?.Dispose(); } catch { }
        }

        private async Task ConnectAsync(CancellationToken cancel)
        {
            Exception? lastEx = null;

            for (int attempt = 1; attempt <= _config.TcpRetryAttempts; attempt++)
            {
                cancel.ThrowIfCancellationRequested();

                try
                {
                    _tcp = new TcpClient();
                    _tcp.NoDelay = true;
                    _tcp.SendTimeout = _config.TcpSendTimeoutSecs * 1000;
                    _tcp.ReceiveTimeout = _config.TcpRecvTimeoutSecs * 1000;

                    using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancel);
                    cts.CancelAfter(TimeSpan.FromSeconds(_config.TcpConnectTimeoutSecs));

                    await _tcp.ConnectAsync(_config.Hostname, _config.Port).WaitAsync(cts.Token).ConfigureAwait(false);

                    Stream baseStream = _tcp.GetStream();

                    if (_config.SslMode == Pop3SslMode.Full)
                    {
                        baseStream = await WrapSslAsync(baseStream, _config.Hostname, _config.SslVerifyServerCert, _config.SslTrustedStaticHashList, cancel).ConfigureAwait(false);
                    }

                    SetStream(baseStream);

                    // Greeting
                    string greeting = await ReadLineAsync(cancel).ConfigureAwait(false);
                    EnsureOk(greeting);

                    if (_config.SslMode == Pop3SslMode.StartTls)
                    {
                        string stlsResp = await SendCommandGetSingleLineResponseAsync("STLS", cancel).ConfigureAwait(false);
                        EnsureOk(stlsResp);

                        Stream sslStream = await WrapSslAsync(_stream!, _config.Hostname, _config.SslVerifyServerCert, _config.SslTrustedStaticHashList, cancel).ConfigureAwait(false);
                        SetStream(sslStream);
                    }

                    return;
                }
                catch (Exception ex)
                {
                    lastEx = ex;
                    await DisposeInternalAsync().ConfigureAwait(false);

                    if (attempt < _config.TcpRetryAttempts)
                    {
                        await Task.Delay(500, cancel).ConfigureAwait(false);
                        continue;
                    }
                }
            }

            throw new Exception(LibCommon.AppendExceptionDetail("APPERROR: Failed to connect POP3 server.", lastEx), lastEx);
        }

        private void SetStream(Stream s)
        {
            try { _writer?.Dispose(); } catch { }
            try { _reader?.Dispose(); } catch { }

            _stream = s;
            _reader = new StreamReader(_stream, Encoding.Latin1, detectEncodingFromByteOrderMarks: false, bufferSize: 4096, leaveOpen: true);
            _writer = new StreamWriter(_stream, Encoding.ASCII, bufferSize: 4096, leaveOpen: true)
            {
                NewLine = "\r\n",
                AutoFlush = true,
            };
        }

        private async Task LoginAsync(ForwardLogger logger, CancellationToken cancel)
        {
            // USER
            string userResp = await SendCommandGetSingleLineResponseAsync($"USER {_config.Username}", cancel).ConfigureAwait(false);
            EnsureOk(userResp);

            // PASS
            string passResp = await SendCommandGetSingleLineResponseAsync($"PASS {_config.Password}", cancel).ConfigureAwait(false);
            EnsureOk(passResp);

            logger.Info("POP3 login succeeded.");
        }

        private async Task SendCommandAsync(string command, CancellationToken cancel)
        {
            if (_writer == null) throw new Exception("APPERROR: POP3 is not connected.");
            await _writer.WriteLineAsync(command).WaitAsync(cancel).ConfigureAwait(false);
        }

        private async Task<string> SendCommandGetSingleLineResponseAsync(string command, CancellationToken cancel)
        {
            await SendCommandAsync(command, cancel).ConfigureAwait(false);
            string resp = await ReadLineAsync(cancel).ConfigureAwait(false);
            return resp;
        }

        private async Task<string> ReadLineAsync(CancellationToken cancel)
        {
            if (_reader == null) throw new Exception("APPERROR: POP3 is not connected.");
            string? line = await _reader.ReadLineAsync().WaitAsync(cancel).ConfigureAwait(false);
            if (line == null) throw new Exception("APPERROR: POP3 server closed connection unexpectedly.");
            return line;
        }

        private static void EnsureOk(string line)
        {
            if (line.StartsWith("+OK", StringComparison.OrdinalIgnoreCase)) return;
            throw new Exception($"APPERROR: POP3 error response: {line}");
        }

        private static async Task<Stream> WrapSslAsync(Stream baseStream, string hostname, bool verifyServerCert, IReadOnlySet<string> trustedStaticHashList, CancellationToken cancel)
        {
            if (baseStream == null) throw new ArgumentNullException(nameof(baseStream));
            if (hostname == null) throw new ArgumentNullException(nameof(hostname));

            RemoteCertificateValidationCallback? callback = null;
            if (verifyServerCert == false)
            {
                callback = (sender, cert, chain, errors) => true;
            }
            else
            {
                callback = (sender, cert, chain, errors) =>
                {
                    if (errors == SslPolicyErrors.None)
                    {
                        return true;
                    }

                    // ★ 静的ハッシュ許可リストに一致する場合は、証明書を信頼してよい [A44FBNFX]
                    if (trustedStaticHashList != null && trustedStaticHashList.Count >= 1)
                    {
                        return IsServerCertificateTrustedByStaticHash(cert, trustedStaticHashList);
                    }

                    return false;
                };
            }

            var ssl = new SslStream(baseStream, leaveInnerStreamOpen: false, userCertificateValidationCallback: callback);

            var opts = new SslClientAuthenticationOptions
            {
                TargetHost = hostname,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            };

            await ssl.AuthenticateAsClientAsync(opts, cancel).ConfigureAwait(false);
            return ssl;
        }

        /// <summary>
        /// サーバー証明書のハッシュ値が、静的許可リストに一致するかどうかを確認します。[A44FBNFX]
        /// </summary>
        /// <param name="certificate">サーバー証明書です。</param>
        /// <param name="trustedStaticHashList">許可する証明書ハッシュ値のセットです。</param>
        /// <returns>一致すれば true です。</returns>
        private static bool IsServerCertificateTrustedByStaticHash(X509Certificate? certificate, IReadOnlySet<string> trustedStaticHashList)
        {
            if (trustedStaticHashList == null) throw new ArgumentNullException(nameof(trustedStaticHashList));
            if (certificate == null) return false;

            try
            {
                byte[] raw = certificate.GetRawCertData();

                byte[] sha1Bytes = SHA1.HashData(raw);
                byte[] sha256Bytes = SHA256.HashData(raw);
                byte[] sha384Bytes = SHA384.HashData(raw);
                byte[] sha512Bytes = SHA512.HashData(raw);

                string sha1Hex = Convert.ToHexString(sha1Bytes).ToLowerInvariant();
                string sha256Hex = Convert.ToHexString(sha256Bytes).ToLowerInvariant();
                string sha384Hex = Convert.ToHexString(sha384Bytes).ToLowerInvariant();
                string sha512Hex = Convert.ToHexString(sha512Bytes).ToLowerInvariant();

                // SHA1 / SHA256 / SHA384 / SHA512
                if (trustedStaticHashList.Contains(sha1Hex) ||
                    trustedStaticHashList.Contains(sha256Hex) ||
                    trustedStaticHashList.Contains(sha384Hex) ||
                    trustedStaticHashList.Contains(sha512Hex))
                {
                    return true;
                }

                // SHA192 は仕様上明示されているため、SHA256/SHA384/SHA512 の先頭 192bit (24bytes) を候補として照合する [A44FBNFX]
                string sha256_192 = sha256Hex.Substring(0, 48);
                string sha384_192 = sha384Hex.Substring(0, 48);
                string sha512_192 = sha512Hex.Substring(0, 48);

                if (trustedStaticHashList.Contains(sha256_192) ||
                    trustedStaticHashList.Contains(sha384_192) ||
                    trustedStaticHashList.Contains(sha512_192))
                {
                    return true;
                }

                return false;
            }
            catch
            {
                return false;
            }
        }
    }
}

/// <summary>
/// メール本文の内部データです。[VZR2Y5BY]
/// </summary>
public sealed class MailMetaData
{
    /// <summary>
    /// メールのサイズ (単位: バイト) です。
    /// </summary>
    public int MailSize;

    /// <summary>
    /// Subject の文字列。デコード済み。無い場合は "" です。
    /// </summary>
    public string Subject = "";

    /// <summary>
    /// Date ヘッダの日時。不明な場合は null です。
    /// </summary>
    public DateTimeOffset? DateTime_Header;

    /// <summary>
    /// Received ヘッダから推定されるメールの配信日時。不明な場合は null です。
    /// </summary>
    public DateTimeOffset? DateTime_Received;

    /// <summary>
    /// メッセージ ID 文字列。無い場合は "" です。
    /// </summary>
    public string MessageId = "";

    /// <summary>
    /// From メールアドレス。不明な場合は null です。
    /// </summary>
    public MailAddress? AddressList_From;

    /// <summary>
    /// To メールアドレス一覧。存在しない場合は空のリストです。
    /// </summary>
    public List<MailAddress> AddressList_To = new List<MailAddress>();

    /// <summary>
    /// Cc メールアドレス一覧。存在しない場合は空のリストです。
    /// </summary>
    public List<MailAddress> AddressList_Cc = new List<MailAddress>();

    /// <summary>
    /// ReplyTo メールアドレス一覧。存在しない場合は空のリストです。
    /// </summary>
    public List<MailAddress> AddressList_ReplyTo = new List<MailAddress>();

    /// <summary>
    /// Return-Path アドレス一覧。存在しない場合は空のリストです。
    /// </summary>
    public List<string> AddressList_ReturnPath = new List<string>();

    /// <summary>
    /// X-Original-To アドレス一覧。存在しない場合は空のリストです。
    /// </summary>
    public List<string> AddressList_OriginalTo = new List<string>();

    /// <summary>
    /// Delivered-To アドレス一覧。存在しない場合は空のリストです。
    /// </summary>
    public List<string> AddressList_DeliveredTo = new List<string>();

    /// <summary>
    /// 平文メールとして処理したときの平文メール本文全文 (デコード済み) です。平文部分が存在しない場合は "" です。
    /// </summary>
    public string PlainTextBody = "";

    /// <summary>
    /// HTML メールとして処理したときの HTML メール本文全文 (デコード済み) です。HTML メールではない場合は "" です。
    /// </summary>
    public string HtmlBody = "";

    /// <summary>
    /// HtmlBody を、全文検索に投入可能な程度に、普通の平文文字列に置換した状態の文字列です。HTML メールではない場合は "" です。
    /// </summary>
    public string HtmlBodyToPlainText = "";

    /// <summary>
    /// 添付ファイル名のリスト。存在しない場合は空のリストです。
    /// </summary>
    public List<string> AttachmentFileNamesList = new List<string>();
}

#endif
