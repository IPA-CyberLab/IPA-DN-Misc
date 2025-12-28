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
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Mail;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using MimeKit;
using MimeKit.Utils;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
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
        Mutex? singleInstanceMutex = null;

        try
        {
            ValidateOptions(options);

            string configFullPath = Path.GetFullPath(options.ConfigPath);
            singleInstanceMutex = AcquireForwardMutexOrThrow(configFullPath);

            ForwardConfig config = await LoadConfigAsync(configFullPath, cancel).ConfigureAwait(false);

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
        finally
        {
            if (singleInstanceMutex != null)
            {
                try { singleInstanceMutex.ReleaseMutex(); } catch { }
                try { singleInstanceMutex.Dispose(); } catch { }
            }
        }
    }

    /// <summary>
    /// loop モードを実行します。[251228_RYJXF4]
    /// </summary>
    /// <param name="configPath">設定ファイルパスです。</param>
    /// <param name="cancel">キャンセル要求です。</param>
    /// <returns>プロセス戻り値です。(0: 成功 / 1: 失敗)</returns>
    public static async Task<int> RunLoopAsync(string configPath, CancellationToken cancel = default)
    {
        ForwardLogger? logger = null;
        string currentLogDir = "";
        bool loopStartLogged = false;
        Mutex? singleInstanceMutex = null;

        try
        {
            if (string.IsNullOrWhiteSpace(configPath))
            {
                throw new Exception("APPERROR: --config is required.");
            }

            string configFullPath = Path.GetFullPath(configPath);
            singleInstanceMutex = AcquireForwardMutexOrThrow(configFullPath);

            int loopCount = 0;
            int backoffSeconds = 1;
            bool hadFatalErrorLastCycle = false;

            while (true)
            {
                cancel.ThrowIfCancellationRequested();

                loopCount++;

                long startTick = Environment.TickCount64;

                bool cycleStartLogged = false;
                bool loopErrorCountReset = false;
                Exception? cycleException = null;
                ForwardConfig? config = null;

                try
                {
                    // ★ ループ 1 回転ごとに config を再読み込みする [251228_SUS8DF]
                    config = await LoadConfigAsync(configFullPath, cancel).ConfigureAwait(false);

                    if (logger == null || string.Equals(currentLogDir, config.Generic.LogDir, StringComparison.OrdinalIgnoreCase) == false)
                    {
                        logger = new ForwardLogger(config.Generic.LogDir);
                        currentLogDir = config.Generic.LogDir;
                    }

                    if (loopStartLogged == false)
                    {
                        logger.Info($"loop mode started. config = {config.ConfigFilePath}");
                        loopStartLogged = true;
                    }

                    EnsureLoopCycleStartLog(logger, loopCount, ref cycleStartLogged, ref loopErrorCountReset);

                    await RunForwardInternalAsync(config, logger, cancel).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    cycleException = ex;

                    string msg = LibCommon.AppendExceptionDetail("APPERROR: Unhandled exception in forward mode during loop cycle.", ex);

                    if (logger != null)
                    {
                        EnsureLoopCycleStartLog(logger, loopCount, ref cycleStartLogged, ref loopErrorCountReset);
                        logger.Error(msg);
                    }
                    else
                    {
                        try { ForwardLogger.WriteErrorToConsoleOnly(msg); } catch { }
                    }
                }

                if (logger != null)
                {
                    EnsureLoopCycleStartLog(logger, loopCount, ref cycleStartLogged, ref loopErrorCountReset);
                }

                double elapsedSecs = (Environment.TickCount64 - startTick) / 1000.0;
                string elapsedText = elapsedSecs.ToString("0.0", CultureInfo.InvariantCulture);

                if (logger != null)
                {
                    logger.Info($"loop mode cycle finished. count={loopCount}, elapsed_secs={elapsedText}");
                }

                long cycleErrorCount = logger != null ? logger.ConsumeLoopErrorCount() : 0;
                bool hasFatalError = cycleException != null || cycleErrorCount > 0;

                if (hasFatalError)
                {
                    if (hadFatalErrorLastCycle)
                    {
                        backoffSeconds = Math.Min(backoffSeconds * 2, 180);
                    }
                    else
                    {
                        backoffSeconds = 1;
                    }

                    hadFatalErrorLastCycle = true;

                    string reason = cycleException != null
                        ? LibCommon.AppendExceptionDetail("fatal error occurred in forward cycle.", cycleException)
                        : $"fatal error occurred in forward cycle. ErrorLogCount={cycleErrorCount}";

                    if (logger != null)
                    {
                        logger.Error($"loop mode will sleep {backoffSeconds} seconds due to fatal error. {reason}");
                    }
                    else
                    {
                        try { ForwardLogger.WriteErrorToConsoleOnly($"APPERROR: loop mode will sleep {backoffSeconds} seconds due to fatal error. {reason}"); } catch { }
                    }

                    await Task.Delay(TimeSpan.FromSeconds(backoffSeconds), cancel).ConfigureAwait(false);
                }
                else
                {
                    hadFatalErrorLastCycle = false;
                    backoffSeconds = 1;

                    double jitter = 0.75 + (Random.Shared.NextDouble() * 0.5);
                    int delayMsecs = (int)Math.Round(1000 * jitter);
                    if (delayMsecs <= 0) delayMsecs = 1;

                    await Task.Delay(delayMsecs, cancel).ConfigureAwait(false);
                }
            }
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
            // loop モードでは、Error ログ形式でユーザーに通知する (可能ならログファイルにも保存する)
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
        finally
        {
            if (singleInstanceMutex != null)
            {
                try { singleInstanceMutex.ReleaseMutex(); } catch { }
                try { singleInstanceMutex.Dispose(); } catch { }
            }
        }
    }

    /// <summary>
    /// loop サイクル開始ログの出力とエラーカウント初期化を行ないます。
    /// </summary>
    /// <param name="logger">ロガーです。</param>
    /// <param name="loopCount">ループ回数です。</param>
    /// <param name="startLogged">開始ログ出力済みフラグです。</param>
    /// <param name="errorCountReset">エラーカウント初期化済みフラグです。</param>
    private static void EnsureLoopCycleStartLog(ForwardLogger logger, int loopCount, ref bool startLogged, ref bool errorCountReset)
    {
        if (logger == null) throw new ArgumentNullException(nameof(logger));

        if (errorCountReset == false)
        {
            // ★ ループ 1 回分の Error ログカウントをリセットしてから実行する
            logger.ConsumeLoopErrorCount();
            errorCountReset = true;
        }

        if (startLogged == false)
        {
            logger.Info($"loop mode cycle started. count={loopCount}");
            startLogged = true;
        }
    }

    /// <summary>
    /// check モードを実行します。[251222_ZYMQ4U]
    /// </summary>
    /// <param name="configPath">設定ファイルパスです。</param>
    /// <param name="cancel">キャンセル要求です。</param>
    /// <returns>プロセス戻り値です。(0: 成功 / 1: 失敗)</returns>
    public static async Task<int> RunCheckAsync(string configPath, CancellationToken cancel = default)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(configPath))
            {
                throw new Exception("APPERROR: --config is required.");
            }

            ForwardConfig config = await LoadConfigAsync(configPath, cancel).ConfigureAwait(false);

            ExecuteUserFilterForCheckIfConfigured(config);

            Console.WriteLine("Config check succeeded.");
            return 0;
        }
        catch (Exception ex)
        {
            string msg = ex.Message ?? "Unknown error.";
            if (msg.StartsWith("APPERROR:", StringComparison.OrdinalIgnoreCase) == false)
            {
                msg = "APPERROR: " + msg;
            }

            try { Console.Error.WriteLine(msg); } catch { }
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
    /// forward の多重起動防止のためのグローバル Mutex を取得します。[251224_DDQDE9]
    /// </summary>
    /// <param name="configFullPath">設定ファイルのフルパスです。</param>
    /// <returns>取得した Mutex です。</returns>
    private static Mutex AcquireForwardMutexOrThrow(string configFullPath)
    {
        if (string.IsNullOrWhiteSpace(configFullPath))
        {
            throw new Exception("APPERROR: config path is empty.");
        }

        string normalized = configFullPath.Trim().ToUpperInvariant();
        string hash = ComputeSha1Hex(Encoding.UTF8.GetBytes(normalized));
        string mutexName = BuildForwardMutexName(hash);

        bool createdNew;
        var mutex = new Mutex(initiallyOwned: false, name: mutexName, createdNew: out createdNew);

        bool acquired;
        try
        {
            acquired = mutex.WaitOne(0);
        }
        catch (AbandonedMutexException)
        {
            // 異常終了で放棄された場合は取得済みとみなす
            acquired = true;
        }

        if (acquired == false)
        {
            mutex.Dispose();
            throw new Exception($"APPERROR: Forward mode is already running for this config file: {configFullPath}");
        }

        return mutex;
    }

    /// <summary>
    /// forward の多重起動防止用の Mutex 名を構成します。
    /// </summary>
    /// <param name="hash">設定ファイルパスから導出したハッシュです。</param>
    /// <returns>Mutex 名です。</returns>
    private static string BuildForwardMutexName(string hash)
    {
        if (hash == null) throw new ArgumentNullException(nameof(hash));

        string baseName = $"dn_pop3_to_gmail_forwarder.forward.{hash}";

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            // Windows ではグローバル名前空間を明示する
            return "Global\\" + baseName;
        }
        else
        {
            return baseName;
        }
    }

    /// <summary>
    /// check モードにおけるユーザーフィルタのコンパイルと 1 回実行を行ないます。[251222_ZYMQ4U]
    /// </summary>
    /// <param name="config">設定データです。</param>
    private static void ExecuteUserFilterForCheckIfConfigured(ForwardConfig config)
    {
        if (config == null) throw new ArgumentNullException(nameof(config));

        string sourceCode = config.Filter?.FilterSourceCode ?? "";
        if (string.IsNullOrWhiteSpace(sourceCode))
        {
            return;
        }

        MailMetaData dummyMail = BuildDummyMailMetaDataForCheck();

        var param = new MailForwardFilterParam
        {
            Mail = dummyMail,
        };

        try
        {
            MailForwardFilterResult? result = LibMailFilterExec.CompileAndInvokeUserFilter(sourceCode, param);
            if (result == null)
            {
                throw new Exception("APPERROR: User filter returned null.");
            }

            if (result.LabelList == null)
            {
                result.LabelList = new HashSet<string>();
            }
        }
        catch (Exception ex)
        {
            string msg = "APPERROR: User filter compile or execution failed.";
            if (string.IsNullOrWhiteSpace(config.Filter?.FilterCSharpFilePath) == false)
            {
                msg += $" FilterFile={config.Filter.FilterCSharpFilePath}";
            }
            throw new Exception(LibCommon.AppendExceptionDetail(msg, ex), ex);
        }
    }

    /// <summary>
    /// check モードでユーザーフィルタに渡すダミーの MailMetaData を生成します。
    /// </summary>
    /// <returns>ダミーの MailMetaData です。</returns>
    private static MailMetaData BuildDummyMailMetaDataForCheck()
    {
        // ★ 乱数で生成したあり得ないようなサンプルデータを作成する [251222_ZYMQ4U]
        string token = Guid.NewGuid().ToString("N");
        string shortToken = token.Substring(0, 8);
        string domain = "example.invalid";

        int mailSize = Random.Shared.Next(1000, 500000);

        var meta = new MailMetaData
        {
            MailSize = mailSize,
            Subject = $"DUMMY_SUBJECT_{token}",
            DateTime_Header = DateTimeOffset.Now.AddMinutes(-Random.Shared.Next(1, 300)),
            DateTime_Received = DateTimeOffset.Now,
            MessageId = $"<{token}@{domain}>",
            AddressList_From = new MailAddress($"from_{shortToken}@{domain}", $"Dummy From {shortToken}"),
            AddressList_To = new List<MailAddress>(),
            AddressList_Cc = new List<MailAddress>(),
            AddressList_ReplyTo = new List<MailAddress>(),
            AddressList_ReturnPath = new List<string>(),
            AddressList_OriginalTo = new List<string>(),
            AddressList_DeliveredTo = new List<string>(),
            PlainTextBody = $"DUMMY_PLAIN_BODY_{token}",
            HtmlBody = $"<html><body><p>DUMMY_HTML_BODY_{token}</p></body></html>",
            HtmlBodyToPlainText = $"DUMMY_HTML_PLAIN_{token}",
            AttachmentFileNamesList = new List<string>(),
        };

        meta.AddressList_To.Add(new MailAddress($"to_{shortToken}@{domain}"));
        meta.AddressList_To.Add(new MailAddress($"to_{shortToken}_2@{domain}"));

        meta.AddressList_Cc.Add(new MailAddress($"cc_{shortToken}@{domain}"));
        meta.AddressList_ReplyTo.Add(new MailAddress($"reply_{shortToken}@{domain}"));

        meta.AddressList_ReturnPath.Add($"return_{shortToken}@{domain}");
        meta.AddressList_OriginalTo.Add($"original_{shortToken}@{domain}");
        meta.AddressList_DeliveredTo.Add($"delivered_{shortToken}@{domain}");

        meta.AttachmentFileNamesList.Add($"dummy_{shortToken}.txt");
        meta.AttachmentFileNamesList.Add($"dummy_{shortToken}.zip");

        return meta;
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

            // [WZZM4P46] STAT の次に LIST を取得し、RETR/DELE は LIST の MessageNo を用いる
            List<Pop3Client.Pop3MessageListItem> mailList = await pop3.ListAsync(cancel).ConfigureAwait(false);

            if (mailList.Count <= 0)
            {
                logger.Info("No messages on POP3 server.");
                return;
            }

            int totalThisLogin = mailList.Count;
            int batchCount = Math.Min(totalThisLogin, config.Pop3.MaxBatchMailsPerLogin);

            for (int i = 0; i < batchCount; i++)
            {
                cancel.ThrowIfCancellationRequested();

                int indexInThisLogin = i + 1;
                int messageNo = mailList[i].MessageNo;
                int listedSize = mailList[i].MailSize;

                logger.Info($"POP3 RETR: index={indexInThisLogin}/{totalThisLogin}, msg_no={messageNo}, size={listedSize}");

                byte[] rawMail = await pop3.RetrieveMessageAsync(messageNo, cancel).ConfigureAwait(false);

                logger.Info($"POP3 RETR OK: size={rawMail.Length}");

                DateTimeOffset fetchedNow = DateTimeOffset.Now;

                MailMetaData meta = ParseMailMetaDataBestEffort(rawMail, fetchedNow);

                logger.Info(BuildMailMetaSummary("POP3 mail meta", meta));

                MailForwardFilterResult filterResult = ExecuteMailFilter(config, meta, logger);

                await SaveArchiveAsync(config, meta, filterResult, rawMail, fetchedNow, logger, cancel).ConfigureAwait(false);

                // Gmail 転送 (大きすぎる場合はスキップ)
                if (rawMail.Length > config.Gmail.GmailMaxMailSize)
                {
                    logger.Error(BuildMailMetaSummary($"Mail size exceeds gmail_max_mail_size={config.Gmail.GmailMaxMailSize}. Gmail import skipped", meta));
                }
                else
                {
                    string accessToken = await EnsureGmailAccessTokenAsync(config, logger, cancel).ConfigureAwait(false);
                    GmailImportOutcome importOutcome = await GmailApiImportAsync(config, accessToken, rawMail, meta, filterResult, cancel).ConfigureAwait(false);
                    switch (importOutcome)
                    {
                        case GmailImportOutcome.ImportedOriginal:
                            logger.Info(BuildMailMetaSummary("Gmail import completed", meta));
                            break;
                        case GmailImportOutcome.ImportedAfterAttachmentRemovalStepA:
                            logger.Info(BuildMailMetaSummary("Gmail import completed after attachment removal step (a)", meta));
                            break;
                        case GmailImportOutcome.ImportedAfterAttachmentRemovalStepB:
                            logger.Info(BuildMailMetaSummary("Gmail import completed after attachment removal step (b)", meta));
                            break;
                        case GmailImportOutcome.ImportedAfterAttachmentRemovalStepC:
                            logger.Info(BuildMailMetaSummary("Gmail import completed after attachment removal step (c)", meta));
                            break;
                        case GmailImportOutcome.ImportedSystemMessageInstead:
                            logger.Error(BuildMailMetaSummary("Failed to import mail to Gmail server. Imported a system message instead", meta));
                            break;
                        default:
                            throw new Exception($"APPERROR: Unknown Gmail import outcome: {importOutcome}");
                    }
                }

                // POP3 削除
                await pop3.DeleteMessageAsync(messageNo, cancel).ConfigureAwait(false);
                logger.Info(BuildMailMetaSummary("POP3 DELE completed", meta));

                // 統計情報記録と自動 tar アーカイブ [251224_CKS4SV]
                bool isFirstToday = await UpdateStatInfoAsync(config, meta, logger, DateTimeOffset.Now, cancel).ConfigureAwait(false);
                if (isFirstToday && config.Generic.ArchiveEnableTar)
                {
                    await RunAutoTarArchiveAsync(config, logger, cancel).ConfigureAwait(false);
                }

                totalProcessed++;
            }

            // max_batch_mails_per_login を超えるメールがある場合は、QUIT して再ログインする
            if (totalThisLogin > batchCount)
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
                    foreach (string addr in ExtractMailAddressStringsFromHeaderValue(v))
                    {
                        meta.AddressList_ReturnPath.Add(addr);
                    }
                }
            }
            catch { }

            try
            {
                foreach (string v in GetHeaderValues(message, "X-Original-To"))
                {
                    foreach (string addr in ExtractMailAddressStringsFromHeaderValue(v))
                    {
                        meta.AddressList_OriginalTo.Add(addr);
                    }
                }
            }
            catch { }

            try
            {
                foreach (string v in GetHeaderValues(message, "Delivered-To"))
                {
                    foreach (string addr in ExtractMailAddressStringsFromHeaderValue(v))
                    {
                        meta.AddressList_DeliveredTo.Add(addr);
                    }
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

            // DateTime_Received が不明な場合は null のままにする (アーカイブ命名側で仕様 [CQVFZY4W] に従い扱う)
        }
        catch
        {
            // ★ 完全にパースに失敗した場合は、本文はメールバイナリを UTF-8 で無理矢理デコードしたものを入れる [AC579L84]
            meta.PlainTextBody = Encoding.UTF8.GetString(rawMail);
            // DateTime_Received は不明なので null のままにする (アーカイブ命名側で仕様 [CQVFZY4W] に従い扱う)
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
    /// Return-Path / X-Original-To / Delivered-To のヘッダ値から、メールアドレス文字列を抽出します。[SS9R4XHX]
    /// </summary>
    /// <param name="headerValue">ヘッダ値です。</param>
    /// <returns>抽出されたアドレス文字列一覧です。</returns>
    private static IEnumerable<string> ExtractMailAddressStringsFromHeaderValue(string headerValue)
    {
        if (headerValue == null) throw new ArgumentNullException(nameof(headerValue));

        string s = headerValue.Trim();
        if (string.IsNullOrWhiteSpace(s))
        {
            yield break;
        }

        // [SS9R4XHX] "<...>" が含まれる場合は、その中身のみを抽出する。("<>" は空文字を格納)
        bool foundAngleBracketPair = false;
        int i = 0;

        while (true)
        {
            int lt = s.IndexOf('<', i);
            if (lt < 0) break;

            int gt = s.IndexOf('>', lt + 1);
            if (gt < 0) break;

            foundAngleBracketPair = true;

            string inner = s.Substring(lt + 1, gt - lt - 1).Trim();
            yield return inner;

            i = gt + 1;
            if (i >= s.Length) break;
        }

        // "<...>" が 1 つも無い場合は、ヘッダ値全体をそのまま利用する
        if (foundAngleBracketPair == false)
        {
            yield return s;
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
    /// メールフィルタを実行し、フィルタ結果を取得します。[251222_ZXH7N7]
    /// </summary>
    /// <param name="config">設定です。</param>
    /// <param name="meta">メールメタデータです。</param>
    /// <param name="logger">ロガーです。</param>
    /// <returns>フィルタ結果です。(常に null 以外)</returns>
    private static MailForwardFilterResult ExecuteMailFilter(ForwardConfig config, MailMetaData meta, ForwardLogger logger)
    {
        if (config == null) throw new ArgumentNullException(nameof(config));
        if (meta == null) throw new ArgumentNullException(nameof(meta));
        if (logger == null) throw new ArgumentNullException(nameof(logger));

        string sourceCode = config.Filter?.FilterSourceCode ?? "";
        if (string.IsNullOrWhiteSpace(sourceCode))
        {
            return new MailForwardFilterResult();
        }

        try
        {
            var param = new MailForwardFilterParam
            {
                Mail = meta,
            };

            MailForwardFilterResult? result = LibMailFilterExec.CompileAndInvokeUserFilter(sourceCode, param);

            if (result == null)
            {
                logger.Error(BuildMailMetaSummary("User filter returned null. Using default filter result", meta));
                return new MailForwardFilterResult();
            }

            if (result.LabelList == null)
            {
                result.LabelList = new HashSet<string>();
            }

            return result;
        }
        catch (Exception ex)
        {
            string msg = BuildMailMetaSummary("User filter execution failed. Using default filter result", meta);
            if (string.IsNullOrWhiteSpace(config.Filter?.FilterCSharpFilePath) == false)
            {
                msg += $" FilterFile={config.Filter.FilterCSharpFilePath}";
            }
            msg += " Exception: " + ex.ToString();
            logger.Error(msg);
            return new MailForwardFilterResult();
        }
    }

    /// <summary>
    /// アーカイブファイルを書き出します。
    /// </summary>
    /// <param name="config">設定です。</param>
    /// <param name="meta">メタデータです。</param>
    /// <param name="filterResult">フィルタ結果です。</param>
    /// <param name="rawMail">生メールです。</param>
    /// <param name="fetchedNow">取得時刻です。</param>
    /// <param name="logger">ロガーです。</param>
    /// <param name="cancel">キャンセル要求です。</param>
    /// <returns>保存先パスです。</returns>
    private static async Task<string> SaveArchiveAsync(ForwardConfig config, MailMetaData meta, MailForwardFilterResult filterResult, byte[] rawMail, DateTimeOffset fetchedNow, ForwardLogger logger, CancellationToken cancel)
    {
        if (config == null) throw new ArgumentNullException(nameof(config));
        if (meta == null) throw new ArgumentNullException(nameof(meta));
        if (filterResult == null) throw new ArgumentNullException(nameof(filterResult));
        if (rawMail == null) throw new ArgumentNullException(nameof(rawMail));
        if (logger == null) throw new ArgumentNullException(nameof(logger));

        // ★ [CQVFZY4W] DateTime_Received が不明の場合は、「(a) で取得をした時点の日付 + 午前 00:00:00 の時刻」とする
        DateTimeOffset local;
        if (meta.DateTime_Received != null)
        {
            local = meta.DateTime_Received.Value.ToLocalTime();
        }
        else
        {
            DateTimeOffset fetchedLocal = fetchedNow.ToLocalTime();
            local = new DateTimeOffset(fetchedLocal.Year, fetchedLocal.Month, fetchedLocal.Day, 0, 0, 0, fetchedLocal.Offset);
        }

        string yyyyMMdd = local.ToString("yyyyMMdd", CultureInfo.InvariantCulture);
        string hhmmss = local.ToString("HHmmss", CultureInfo.InvariantCulture);

        string metaJsonBody = JsonConvert.SerializeObject(meta, LibCommon.CreateStandardJsonSerializerSettings());
        metaJsonBody = metaJsonBody.Replace("\r\n", "\n").Replace("\r", "\n").TrimEnd('\n');

        if (filterResult.LabelList == null)
        {
            filterResult.LabelList = new HashSet<string>();
        }

        string filterJsonBody = JsonConvert.SerializeObject(filterResult, LibCommon.CreateStandardJsonSerializerSettings());
        filterJsonBody = filterJsonBody.Replace("\r\n", "\n").Replace("\r", "\n").TrimEnd('\n');

        byte[] metaBytes = Encoding.UTF8.GetBytes(metaJsonBody);
        byte[] filterBytes = Encoding.UTF8.GetBytes(filterJsonBody);
        string sha1Hex = ComputeSha1Hex(metaBytes);

        string from64 = BuildFrom64(meta.AddressList_From);

        bool enableGzip = config.Generic.ArchiveEnableGzip;
        string fileName = $"{yyyyMMdd}_{hhmmss}_{sha1Hex}_{from64}.txt";
        if (enableGzip)
        {
            fileName += ".gz";
        }
        string dir = Path.Combine(config.Generic.ArchiveDir, yyyyMMdd);
        string fullPath = Path.Combine(dir, fileName);

        Directory.CreateDirectory(dir);

        byte[] bom = new byte[] { 0xEF, 0xBB, 0xBF };
        byte[] sep = Encoding.ASCII.GetBytes("===================================================================\n");
        byte[] lf2 = Encoding.ASCII.GetBytes("\n\n");
        byte[] beginMeta = Encoding.ASCII.GetBytes("-- BEGIN MailMetaData --\n");
        byte[] endMeta = Encoding.ASCII.GetBytes("\n-- END MailMetaData --\n");
        byte[] beginFilter = Encoding.ASCII.GetBytes("-- BEGIN MailForwardFilterResult --\n");
        byte[] endFilter = Encoding.ASCII.GetBytes("\n-- END MailForwardFilterResult --\n");

        using (var fs = new FileStream(fullPath, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            if (enableGzip)
            {
                // gzip 圧縮を最大圧縮率で有効化する [251224_BEXKU2]
                using var gz = new GZipStream(fs, CompressionLevel.SmallestSize, leaveOpen: false);
                await WriteArchiveContentAsync(gz, bom, lf2, beginMeta, endMeta, beginFilter, endFilter, sep, metaBytes, filterBytes, rawMail, cancel).ConfigureAwait(false);
            }
            else
            {
                await WriteArchiveContentAsync(fs, bom, lf2, beginMeta, endMeta, beginFilter, endFilter, sep, metaBytes, filterBytes, rawMail, cancel).ConfigureAwait(false);
            }
        }

        long size = new FileInfo(fullPath).Length;
        logger.Info($"Archive saved: {fullPath} (size={size})");

        return fullPath;
    }

    /// <summary>
    /// 統計情報を更新し、本日初回かどうかを返します。[251224_CJU4PT][251224_CKS4SV]
    /// </summary>
    /// <param name="config">設定です。</param>
    /// <param name="meta">メタデータです。</param>
    /// <param name="logger">ロガーです。</param>
    /// <param name="now">現在時刻です。</param>
    /// <param name="cancel">キャンセル要求です。</param>
    /// <returns>本日初回の場合は true です。</returns>
    private static async Task<bool> UpdateStatInfoAsync(ForwardConfig config, MailMetaData meta, ForwardLogger logger, DateTimeOffset now, CancellationToken cancel)
    {
        if (config == null) throw new ArgumentNullException(nameof(config));
        if (meta == null) throw new ArgumentNullException(nameof(meta));
        if (logger == null) throw new ArgumentNullException(nameof(logger));

        string statPath = config.Generic.StatFileName;

        LibMailFwdStatInfo stat = new LibMailFwdStatInfo();
        bool loaded = false;

        if (File.Exists(statPath))
        {
            try
            {
                stat = await LibCommon.ReadSingleJsonFileAsync<LibMailFwdStatInfo>(statPath, cancel).ConfigureAwait(false);
                loaded = true;
            }
            catch (Exception ex)
            {
                logger.Error(LibCommon.AppendExceptionDetail($"APPERROR: Failed to read stat file: {statPath}", ex));
                stat = new LibMailFwdStatInfo();
            }
        }

        DateTimeOffset nowLocal = now.ToLocalTime();
        DateTime today = nowLocal.Date;

        bool isFirstToday = true;
        if (loaded)
        {
            DateTime lastLocalDate = stat.LastRunOkDt.ToLocalTime().Date;
            isFirstToday = lastLocalDate < today;
        }

        long errorDelta = logger.ConsumeErrorCount();

        stat.LastRunOkDt = nowLocal;
        stat.NumMails += 1;
        stat.NumErrors += errorDelta;
        stat.TotalMailSize += meta.MailSize;

        JsonSerializerSettings compactSettings = LibCommon.CreateStandardJsonSerializerSettings();
        compactSettings.Formatting = Formatting.None;
        string compactJson = JsonConvert.SerializeObject(stat, compactSettings);
        logger.Info(compactJson);

        try
        {
            await LibCommon.WriteSingleJsonFileByTempAsync(statPath, stat, cancel).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            logger.Error(LibCommon.AppendExceptionDetail($"APPERROR: Failed to write stat file: {statPath}", ex));
        }

        return isFirstToday;
    }

    /// <summary>
    /// 自動 tar アーカイブ機能を実行します。[251224_CCNR2A]
    /// </summary>
    /// <param name="config">設定です。</param>
    /// <param name="logger">ロガーです。</param>
    /// <param name="cancel">キャンセル要求です。</param>
    /// <returns>非同期タスクです。</returns>
    private static async Task RunAutoTarArchiveAsync(ForwardConfig config, ForwardLogger logger, CancellationToken cancel)
    {
        if (config == null) throw new ArgumentNullException(nameof(config));
        if (logger == null) throw new ArgumentNullException(nameof(logger));

        if (config.Generic.ArchiveEnableTar == false)
        {
            return;
        }

        string archiveDir = config.Generic.ArchiveDir;
        if (Directory.Exists(archiveDir) == false)
        {
            return;
        }

        DateTime today = DateTime.Now.Date;
        int passDays = config.Generic.ArchiveEnableTarPassDays;

        var targets = new List<(DateTime Date, string DirPath, string DirName)>();

        foreach (string dir in Directory.GetDirectories(archiveDir))
        {
            string name = Path.GetFileName(dir);
            if (TryParseArchiveDateDirName(name, out DateTime date) == false)
            {
                continue;
            }

            if (date > today)
            {
                continue;
            }

            int daysPassed = (today - date).Days;
            if (daysPassed < passDays)
            {
                continue;
            }

            targets.Add((date, dir, name));
        }

        targets.Sort((a, b) => a.Date.CompareTo(b.Date));

        foreach (var target in targets)
        {
            cancel.ThrowIfCancellationRequested();

            try
            {
                await ProcessTarArchiveDirectoryAsync(target.DirPath, target.DirName, logger, cancel).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                logger.Error(LibCommon.AppendExceptionDetail($"APPERROR: Auto tar archive failed. dir={target.DirPath}", ex));
            }
        }
    }

    /// <summary>
    /// tar 化対象ディレクトリを処理します。[251224_CCNR2A]
    /// </summary>
    /// <param name="dirPath">対象ディレクトリパスです。</param>
    /// <param name="dirName">対象ディレクトリ名 (YYYYMMDD) です。</param>
    /// <param name="logger">ロガーです。</param>
    /// <param name="cancel">キャンセル要求です。</param>
    /// <returns>非同期タスクです。</returns>
    private static async Task ProcessTarArchiveDirectoryAsync(string dirPath, string dirName, ForwardLogger logger, CancellationToken cancel)
    {
        if (dirPath == null) throw new ArgumentNullException(nameof(dirPath));
        if (dirName == null) throw new ArgumentNullException(nameof(dirName));
        if (logger == null) throw new ArgumentNullException(nameof(logger));

        List<FileInfo> files = new List<FileInfo>();
        foreach (string path in Directory.GetFiles(dirPath, "*.txt"))
        {
            files.Add(new FileInfo(path));
        }
        foreach (string path in Directory.GetFiles(dirPath, "*.txt.gz"))
        {
            files.Add(new FileInfo(path));
        }

        if (files.Count <= 0)
        {
            return;
        }

        files.Sort((a, b) => StringComparer.Ordinal.Compare(a.Name, b.Name));

        string tarPath = Path.Combine(dirPath, dirName + ".tar");
        HashSet<string> existingNames = new HashSet<string>(StringComparer.Ordinal);
        long appendOffset = 0;

        if (File.Exists(tarPath))
        {
            TarScanResult scan = ScanTarArchive(tarPath);
            existingNames = scan.EntryNames;
            appendOffset = scan.AppendOffset;
        }

        var appendFiles = new List<FileInfo>();
        var nameSet = new HashSet<string>(existingNames, StringComparer.Ordinal);

        foreach (FileInfo fi in files)
        {
            string name = fi.Name;
            if (nameSet.Contains(name))
            {
                logger.Error($"APPERROR: Auto tar archive duplicate file name. dir={dirPath}, file={name}, tar={tarPath}");
                continue;
            }

            appendFiles.Add(fi);
            nameSet.Add(name);
        }

        if (appendFiles.Count <= 0)
        {
            return;
        }

        TarAppendResult appendResult = await AppendFilesToTarAsync(tarPath, appendOffset, appendFiles, cancel).ConfigureAwait(false);
        if (appendResult.Success == false)
        {
            string fileInfo = string.IsNullOrEmpty(appendResult.FailedFileName) ? "" : $", file={appendResult.FailedFileName}";
            if (appendResult.Exception != null)
            {
                logger.Error(LibCommon.AppendExceptionDetail($"APPERROR: Auto tar archive failed. dir={dirPath}, tar={tarPath}{fileInfo}", appendResult.Exception));
            }
            else
            {
                logger.Error($"APPERROR: Auto tar archive failed. dir={dirPath}, tar={tarPath}{fileInfo}");
            }
            return;
        }

        foreach (FileInfo fi in appendResult.AppendedFiles)
        {
            try
            {
                File.Delete(fi.FullName);
            }
            catch (Exception ex)
            {
                logger.Error(LibCommon.AppendExceptionDetail($"APPERROR: Auto tar archive failed to delete file. dir={dirPath}, file={fi.FullName}", ex));
            }
        }
    }

    /// <summary>
    /// tar 追記処理結果です。
    /// </summary>
    private sealed class TarAppendResult
    {
        /// <summary>
        /// 成功したかどうかです。
        /// </summary>
        public bool Success;

        /// <summary>
        /// 追記したファイル一覧です。
        /// </summary>
        public List<FileInfo> AppendedFiles = new List<FileInfo>();

        /// <summary>
        /// 失敗時のファイル名です。
        /// </summary>
        public string FailedFileName = "";

        /// <summary>
        /// 例外です。
        /// </summary>
        public Exception? Exception;
    }

    /// <summary>
    /// tar ファイルに追記します。[251224_CCNR2A]
    /// </summary>
    /// <param name="tarPath">tar ファイルパスです。</param>
    /// <param name="appendOffset">追記開始オフセットです。</param>
    /// <param name="files">追記するファイル一覧です。</param>
    /// <param name="cancel">キャンセル要求です。</param>
    /// <returns>処理結果です。</returns>
    private static async Task<TarAppendResult> AppendFilesToTarAsync(string tarPath, long appendOffset, List<FileInfo> files, CancellationToken cancel)
    {
        if (tarPath == null) throw new ArgumentNullException(nameof(tarPath));
        if (files == null) throw new ArgumentNullException(nameof(files));

        var result = new TarAppendResult();

        using var fs = new FileStream(tarPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        fs.SetLength(appendOffset);
        fs.Position = appendOffset;

        try
        {
            foreach (FileInfo fi in files)
            {
                cancel.ThrowIfCancellationRequested();

                result.FailedFileName = fi.Name;
                await WriteTarEntryAsync(fs, fi, fi.Name, cancel).ConfigureAwait(false);
                result.AppendedFiles.Add(fi);
            }

            await WriteTarEndBlocksAsync(fs, cancel).ConfigureAwait(false);
            result.Success = true;
            return result;
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Exception = ex;

            // 追記に失敗した場合は、元の終端ブロックに戻す
            try
            {
                fs.SetLength(appendOffset);
                fs.Position = appendOffset;
                await WriteTarEndBlocksAsync(fs, cancel).ConfigureAwait(false);
            }
            catch
            {
                // 復旧失敗は無視 (上位で詳細ログ)
            }

            return result;
        }
    }

    /// <summary>
    /// tar の 2 つの終端ブロックを書き込みます。
    /// </summary>
    /// <param name="stream">書き込み先ストリームです。</param>
    /// <param name="cancel">キャンセル要求です。</param>
    /// <returns>非同期タスクです。</returns>
    private static async Task WriteTarEndBlocksAsync(Stream stream, CancellationToken cancel)
    {
        if (stream == null) throw new ArgumentNullException(nameof(stream));

        byte[] zero = new byte[512];
        await stream.WriteAsync(zero, 0, zero.Length, cancel).ConfigureAwait(false);
        await stream.WriteAsync(zero, 0, zero.Length, cancel).ConfigureAwait(false);
    }

    /// <summary>
    /// tar エントリを書き込みます。
    /// </summary>
    /// <param name="tarStream">tar ストリームです。</param>
    /// <param name="file">対象ファイルです。</param>
    /// <param name="entryName">tar 内のファイル名です。</param>
    /// <param name="cancel">キャンセル要求です。</param>
    /// <returns>非同期タスクです。</returns>
    private static async Task WriteTarEntryAsync(Stream tarStream, FileInfo file, string entryName, CancellationToken cancel)
    {
        if (tarStream == null) throw new ArgumentNullException(nameof(tarStream));
        if (file == null) throw new ArgumentNullException(nameof(file));
        if (entryName == null) throw new ArgumentNullException(nameof(entryName));

        byte[] nameBytes = Encoding.UTF8.GetBytes(entryName);
        DateTimeOffset mtime = new DateTimeOffset(file.LastWriteTimeUtc, TimeSpan.Zero);

        if (nameBytes.Length > 100)
        {
            await WriteTarLongNameAsync(tarStream, entryName, mtime, cancel).ConfigureAwait(false);
        }

        string headerName = entryName;
        if (nameBytes.Length > 100)
        {
            headerName = TruncateUtf8String(entryName, 100);
        }

        byte[] header = BuildTarHeader(headerName, file.Length, mtime, typeFlag: '0');
        await tarStream.WriteAsync(header, 0, header.Length, cancel).ConfigureAwait(false);

        await using (var fs = new FileStream(file.FullName, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            await fs.CopyToAsync(tarStream, 81920, cancel).ConfigureAwait(false);
        }

        long pad = (512 - (file.Length % 512)) % 512;
        if (pad > 0)
        {
            byte[] padBuf = new byte[pad];
            await tarStream.WriteAsync(padBuf, 0, padBuf.Length, cancel).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// GNU tar の LongLink エントリを書き込みます。
    /// </summary>
    /// <param name="tarStream">tar ストリームです。</param>
    /// <param name="longName">長いファイル名です。</param>
    /// <param name="mtime">更新日時です。</param>
    /// <param name="cancel">キャンセル要求です。</param>
    /// <returns>非同期タスクです。</returns>
    private static async Task WriteTarLongNameAsync(Stream tarStream, string longName, DateTimeOffset mtime, CancellationToken cancel)
    {
        if (tarStream == null) throw new ArgumentNullException(nameof(tarStream));
        if (longName == null) throw new ArgumentNullException(nameof(longName));

        byte[] nameBytes = Encoding.UTF8.GetBytes(longName);
        long size = nameBytes.Length + 1;

        byte[] header = BuildTarHeader("././@LongLink", size, mtime, typeFlag: 'L');
        await tarStream.WriteAsync(header, 0, header.Length, cancel).ConfigureAwait(false);

        await tarStream.WriteAsync(nameBytes, 0, nameBytes.Length, cancel).ConfigureAwait(false);
        await tarStream.WriteAsync(new byte[] { 0x00 }, 0, 1, cancel).ConfigureAwait(false);

        long pad = (512 - (size % 512)) % 512;
        if (pad > 0)
        {
            byte[] padBuf = new byte[pad];
            await tarStream.WriteAsync(padBuf, 0, padBuf.Length, cancel).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// tar ヘッダを作成します。
    /// </summary>
    /// <param name="name">ファイル名です。</param>
    /// <param name="size">ファイルサイズです。</param>
    /// <param name="mtime">更新日時です。</param>
    /// <param name="typeFlag">type フラグです。</param>
    /// <returns>tar ヘッダ (512 bytes) です。</returns>
    private static byte[] BuildTarHeader(string name, long size, DateTimeOffset mtime, char typeFlag)
    {
        if (name == null) throw new ArgumentNullException(nameof(name));

        byte[] header = new byte[512];

        WriteTarString(header, 0, 100, name);
        WriteTarOctal(header, 100, 8, 0_000777);
        WriteTarOctal(header, 108, 8, 0);
        WriteTarOctal(header, 116, 8, 0);
        WriteTarOctal(header, 124, 12, size);

        long unixTime = mtime.ToUnixTimeSeconds();
        if (unixTime < 0) unixTime = 0;
        WriteTarOctal(header, 136, 12, unixTime);

        for (int i = 148; i < 156; i++) header[i] = 0x20; // チェックサム計算時は空白

        header[156] = (byte)typeFlag;

        WriteTarString(header, 257, 6, "ustar");
        WriteTarString(header, 263, 2, "00");

        long sum = 0;
        foreach (byte b in header)
        {
            sum += b;
        }

        WriteTarChecksum(header, sum);

        return header;
    }

    /// <summary>
    /// tar ファイル内の既存エントリ名と追記位置を取得します。
    /// </summary>
    /// <param name="tarPath">tar ファイルパスです。</param>
    /// <returns>スキャン結果です。</returns>
    private static TarScanResult ScanTarArchive(string tarPath)
    {
        if (tarPath == null) throw new ArgumentNullException(nameof(tarPath));

        var result = new TarScanResult();

        using var fs = new FileStream(tarPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        byte[] header = new byte[512];
        string pendingLongName = "";

        while (true)
        {
            long headerPos = fs.Position;
            if (ReadExactlyOrEof(fs, header, 0, header.Length) == false)
            {
                result.AppendOffset = fs.Position;
                return result;
            }

            if (IsAllZero(header))
            {
                result.AppendOffset = headerPos;
                return result;
            }

            char typeFlag = (char)header[156];
            if (typeFlag == 'L')
            {
                long size = ParseTarOctal(header, 124, 12);
                byte[] longNameBytes = ReadTarDataBytes(fs, size);
                pendingLongName = Encoding.UTF8.GetString(longNameBytes).TrimEnd('\0');

                long skip = ((size + 511) / 512) * 512 - size;
                if (skip > 0) SkipExactly(fs, skip);
                continue;
            }

            string name;
            if (string.IsNullOrEmpty(pendingLongName) == false)
            {
                name = pendingLongName;
                pendingLongName = "";
            }
            else
            {
                name = ReadNullTerminatedAscii(header, 0, 100);
                string prefix = ReadNullTerminatedAscii(header, 345, 155);
                if (string.IsNullOrEmpty(prefix) == false)
                {
                    name = prefix + "/" + name;
                }
            }

            if (string.IsNullOrEmpty(name) == false)
            {
                result.EntryNames.Add(name);
            }

            long dataSize = ParseTarOctal(header, 124, 12);
            long skipData = ((dataSize + 511) / 512) * 512;
            if (skipData > 0) SkipExactly(fs, skipData);
        }
    }

    /// <summary>
    /// tar データ部を読み取ります。
    /// </summary>
    /// <param name="stream">入力ストリームです。</param>
    /// <param name="size">読み取るサイズです。</param>
    /// <returns>読み取ったバイト配列です。</returns>
    private static byte[] ReadTarDataBytes(Stream stream, long size)
    {
        if (stream == null) throw new ArgumentNullException(nameof(stream));
        if (size < 0 || size > int.MaxValue) throw new Exception("APPERROR: tar entry size is invalid.");

        int len = (int)size;
        byte[] buf = new byte[len];
        int total = 0;
        while (total < len)
        {
            int r = stream.Read(buf, total, len - total);
            if (r <= 0)
            {
                throw new EndOfStreamException("APPERROR: Unexpected end of tar stream.");
            }
            total += r;
        }
        return buf;
    }

    /// <summary>
    /// tar スキャン結果です。
    /// </summary>
    private sealed class TarScanResult
    {
        /// <summary>
        /// tar 内の既存エントリ名一覧です。
        /// </summary>
        public HashSet<string> EntryNames = new HashSet<string>(StringComparer.Ordinal);

        /// <summary>
        /// 追記開始オフセットです。
        /// </summary>
        public long AppendOffset;
    }

    /// <summary>
    /// YYYYMMDD 形式のディレクトリ名をパースします。
    /// </summary>
    /// <param name="dirName">ディレクトリ名です。</param>
    /// <param name="date">パース結果の日付です。</param>
    /// <returns>パースできた場合は true です。</returns>
    private static bool TryParseArchiveDateDirName(string dirName, out DateTime date)
    {
        date = default;
        if (string.IsNullOrWhiteSpace(dirName)) return false;

        return DateTime.TryParseExact(dirName, "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.None, out date);
    }

    /// <summary>
    /// tar 用の文字列を ASCII で書き込みます。
    /// </summary>
    /// <param name="buf">バッファです。</param>
    /// <param name="offset">書き込み開始位置です。</param>
    /// <param name="len">最大長です。</param>
    /// <param name="value">書き込む文字列です。</param>
    private static void WriteTarString(byte[] buf, int offset, int len, string value)
    {
        if (buf == null) throw new ArgumentNullException(nameof(buf));
        if (value == null) value = "";

        byte[] src = Encoding.ASCII.GetBytes(value);
        int copyLen = Math.Min(len, src.Length);
        Array.Copy(src, 0, buf, offset, copyLen);
    }

    /// <summary>
    /// tar 用の 8 進数フィールドを書き込みます。
    /// </summary>
    /// <param name="buf">バッファです。</param>
    /// <param name="offset">書き込み開始位置です。</param>
    /// <param name="len">長さです。</param>
    /// <param name="value">値です。</param>
    private static void WriteTarOctal(byte[] buf, int offset, int len, long value)
    {
        if (buf == null) throw new ArgumentNullException(nameof(buf));
        if (len <= 0) return;

        string oct = Convert.ToString(value, 8);
        if (oct.Length > len - 1)
        {
            throw new Exception("APPERROR: tar octal field overflow.");
        }

        string s = oct.PadLeft(len - 1, '0');
        byte[] src = Encoding.ASCII.GetBytes(s);
        Array.Copy(src, 0, buf, offset, src.Length);
        buf[offset + len - 1] = 0;
    }

    /// <summary>
    /// tar 用のチェックサムフィールドを書き込みます。
    /// </summary>
    /// <param name="buf">バッファです。</param>
    /// <param name="checksum">チェックサム値です。</param>
    private static void WriteTarChecksum(byte[] buf, long checksum)
    {
        if (buf == null) throw new ArgumentNullException(nameof(buf));

        string oct = Convert.ToString(checksum, 8);
        oct = oct.PadLeft(6, '0');
        byte[] src = Encoding.ASCII.GetBytes(oct);
        Array.Copy(src, 0, buf, 148, src.Length);
        buf[148 + 6] = 0;
        buf[148 + 7] = (byte)' ';
    }

    /// <summary>
    /// UTF-8 文字列を指定バイト数で切り詰めます。
    /// </summary>
    /// <param name="text">入力文字列です。</param>
    /// <param name="maxBytes">最大バイト数です。</param>
    /// <returns>切り詰め後の文字列です。</returns>
    private static string TruncateUtf8String(string text, int maxBytes)
    {
        if (text == null) throw new ArgumentNullException(nameof(text));
        if (maxBytes <= 0) return "";

        byte[] bytes = Encoding.UTF8.GetBytes(text);
        if (bytes.Length <= maxBytes) return text;

        int cut = maxBytes;
        while (cut > 0 && (bytes[cut - 1] & 0xC0) == 0x80)
        {
            cut--;
        }

        if (cut <= 0) return "";

        return Encoding.UTF8.GetString(bytes, 0, cut);
    }

    /// <summary>
    /// アーカイブファイルの内容を書き込みます。
    /// </summary>
    /// <param name="stream">書き込み先ストリームです。</param>
    /// <param name="bom">UTF-8 BOM です。</param>
    /// <param name="lf2">2 行改行データです。</param>
    /// <param name="beginMeta">MailMetaData の開始マーカーです。</param>
    /// <param name="endMeta">MailMetaData の終了マーカーです。</param>
    /// <param name="beginFilter">MailForwardFilterResult の開始マーカーです。</param>
    /// <param name="endFilter">MailForwardFilterResult の終了マーカーです。</param>
    /// <param name="sep">区切り線です。</param>
    /// <param name="metaBytes">MailMetaData の JSON バイト列です。</param>
    /// <param name="filterBytes">MailForwardFilterResult の JSON バイト列です。</param>
    /// <param name="rawMail">生メールのバイト列です。</param>
    /// <param name="cancel">キャンセル要求です。</param>
    /// <returns>非同期タスクです。</returns>
    private static async Task WriteArchiveContentAsync(Stream stream, byte[] bom, byte[] lf2, byte[] beginMeta, byte[] endMeta, byte[] beginFilter, byte[] endFilter, byte[] sep, byte[] metaBytes, byte[] filterBytes, byte[] rawMail, CancellationToken cancel)
    {
        if (stream == null) throw new ArgumentNullException(nameof(stream));
        if (bom == null) throw new ArgumentNullException(nameof(bom));
        if (lf2 == null) throw new ArgumentNullException(nameof(lf2));
        if (beginMeta == null) throw new ArgumentNullException(nameof(beginMeta));
        if (endMeta == null) throw new ArgumentNullException(nameof(endMeta));
        if (beginFilter == null) throw new ArgumentNullException(nameof(beginFilter));
        if (endFilter == null) throw new ArgumentNullException(nameof(endFilter));
        if (sep == null) throw new ArgumentNullException(nameof(sep));
        if (metaBytes == null) throw new ArgumentNullException(nameof(metaBytes));
        if (filterBytes == null) throw new ArgumentNullException(nameof(filterBytes));
        if (rawMail == null) throw new ArgumentNullException(nameof(rawMail));

        await stream.WriteAsync(bom, 0, bom.Length, cancel).ConfigureAwait(false);
        await stream.WriteAsync(lf2, 0, lf2.Length, cancel).ConfigureAwait(false);

        await stream.WriteAsync(beginMeta, 0, beginMeta.Length, cancel).ConfigureAwait(false);
        await stream.WriteAsync(metaBytes, 0, metaBytes.Length, cancel).ConfigureAwait(false);
        await stream.WriteAsync(endMeta, 0, endMeta.Length, cancel).ConfigureAwait(false);

        await stream.WriteAsync(lf2, 0, lf2.Length, cancel).ConfigureAwait(false);

        await stream.WriteAsync(beginFilter, 0, beginFilter.Length, cancel).ConfigureAwait(false);
        await stream.WriteAsync(filterBytes, 0, filterBytes.Length, cancel).ConfigureAwait(false);
        await stream.WriteAsync(endFilter, 0, endFilter.Length, cancel).ConfigureAwait(false);

        await stream.WriteAsync(lf2, 0, lf2.Length, cancel).ConfigureAwait(false);
        await stream.WriteAsync(sep, 0, sep.Length, cancel).ConfigureAwait(false);

        await stream.WriteAsync(rawMail, 0, rawMail.Length, cancel).ConfigureAwait(false);
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
    /// Gmail API import の結果種別です。[ULP8TK5N][GTFE562C]
    /// </summary>
    private enum GmailImportOutcome
    {
        /// <summary>
        /// 元メールのインポートに成功しました。
        /// </summary>
        ImportedOriginal = 0,

        /// <summary>
        /// 添付ファイル削除 (a) 後のインポートに成功しました。[GTFE562C]
        /// </summary>
        ImportedAfterAttachmentRemovalStepA,

        /// <summary>
        /// 添付ファイル削除 (b) 後のインポートに成功しました。[GTFE562C]
        /// </summary>
        ImportedAfterAttachmentRemovalStepB,

        /// <summary>
        /// 添付ファイル削除 (c) 後のインポートに成功しました。[GTFE562C]
        /// </summary>
        ImportedAfterAttachmentRemovalStepC,

        /// <summary>
        /// 元メールのインポートには失敗しましたが、システムメッセージのインポートに成功しました。[GTFE562C][HA7DHHGE]
        /// </summary>
        ImportedSystemMessageInstead,
    }

    /// <summary>
    /// Gmail API import 用のメタデータ JSON を生成します。[251222_ZXH7N7][251223_BVHM5V]
    /// </summary>
    /// <param name="httpClient">HTTP クライアントです。</param>
    /// <param name="accessToken">アクセストークンです。</param>
    /// <param name="filterResult">フィルタ結果です。</param>
    /// <param name="cancel">キャンセル要求です。</param>
    /// <returns>JSON 文字列です。(改行は LF のみ)</returns>
    private static async Task<string> BuildGmailImportMetaJsonAsync(HttpClient httpClient, string accessToken, MailForwardFilterResult filterResult, CancellationToken cancel)
    {
        if (httpClient == null) throw new ArgumentNullException(nameof(httpClient));
        if (accessToken == null) throw new ArgumentNullException(nameof(accessToken));
        if (filterResult == null) throw new ArgumentNullException(nameof(filterResult));

        List<string> labelNames = BuildGmailLabelNameList(filterResult);
        List<string> labelIds = await ResolveGmailLabelIdsAsync(httpClient, accessToken, labelNames, cancel).ConfigureAwait(false);

        string metaJson = JsonConvert.SerializeObject(new { labelIds = labelIds }, LibCommon.CreateStandardJsonSerializerSettings());
        metaJson = metaJson.Replace("\r\n", "\n").Replace("\r", "\n");

        return metaJson;
    }

    /// <summary>
    /// Gmail API import のラベル名一覧を生成します。[251222_ZXH7N7]
    /// </summary>
    /// <param name="filterResult">フィルタ結果です。</param>
    /// <returns>ラベル名一覧です。</returns>
    private static List<string> BuildGmailLabelNameList(MailForwardFilterResult filterResult)
    {
        if (filterResult == null) throw new ArgumentNullException(nameof(filterResult));

        var list = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        AddGmailLabelIfMissing(seen, list, "INBOX");

        if (filterResult.MarkAsRead == false)
        {
            AddGmailLabelIfMissing(seen, list, "UNREAD");
        }

        if (filterResult.LabelList != null && filterResult.LabelList.Count >= 1)
        {
            var customLabels = filterResult.LabelList
                .Where(x => string.IsNullOrWhiteSpace(x) == false)
                .Select(x => (x ?? "").Trim())
                .Where(x => x.Length >= 1)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(x => x, StringComparer.Ordinal)
                .ToList();

            foreach (string label in customLabels)
            {
                AddGmailLabelIfMissing(seen, list, label);
            }
        }

        return list;
    }

    /// <summary>
    /// labelIds にラベルを追加します。(重複や空文字は追加しません)
    /// </summary>
    /// <param name="seen">追加済み判定用のセットです。</param>
    /// <param name="list">出力先リストです。</param>
    /// <param name="label">追加するラベル文字列です。</param>
    private static void AddGmailLabelIfMissing(HashSet<string> seen, List<string> list, string label)
    {
        if (seen == null) throw new ArgumentNullException(nameof(seen));
        if (list == null) throw new ArgumentNullException(nameof(list));
        if (string.IsNullOrWhiteSpace(label)) return;

        string trimmed = label.Trim();
        if (trimmed.Length == 0) return;

        if (seen.Add(trimmed))
        {
            list.Add(trimmed);
        }
    }

    /// <summary>
    /// ラベル名階層の作成順序リストを生成します。[251223_CTSHY7]
    /// </summary>
    /// <param name="labelNames">ラベル名一覧です。</param>
    /// <returns>作成順序のラベル名一覧です。</returns>
    private static List<string> BuildGmailLabelHierarchyList(List<string> labelNames)
    {
        var list = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (labelNames == null) return list;

        foreach (string rawName in labelNames)
        {
            string name = (rawName ?? "").Trim();
            if (name.Length == 0) continue;

            List<string> hierarchy = ExpandGmailLabelNameHierarchy(name);
            foreach (string item in hierarchy)
            {
                if (seen.Add(item))
                {
                    list.Add(item);
                }
            }
        }

        return list;
    }

    /// <summary>
    /// ラベル名を「/」区切りで分解し、親→子の順で階層名を生成します。[251223_CTSHY7]
    /// </summary>
    /// <param name="labelName">ラベル名です。</param>
    /// <returns>階層ラベル名一覧です。</returns>
    private static List<string> ExpandGmailLabelNameHierarchy(string labelName)
    {
        var list = new List<string>();

        if (string.IsNullOrWhiteSpace(labelName)) return list;

        string[] parts = labelName.Split(new[] { '/' }, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0) return list;

        var sb = new StringBuilder();
        for (int i = 0; i < parts.Length; i++)
        {
            string part = parts[i].Trim();
            if (part.Length == 0) continue;

            if (sb.Length > 0) sb.Append('/');
            sb.Append(part);

            list.Add(sb.ToString());
        }

        if (list.Count == 0)
        {
            list.Add(labelName.Trim());
        }

        return list;
    }

    /// <summary>
    /// Gmail のシステムラベル名かどうかを判定します。
    /// </summary>
    /// <param name="labelName">ラベル名です。</param>
    /// <returns>システムラベルなら true です。</returns>
    private static bool IsGmailSystemLabelName(string labelName)
    {
        if (string.IsNullOrWhiteSpace(labelName)) return false;
        return GmailSystemLabelNameSet.Contains(labelName.Trim());
    }

    /// <summary>
    /// Gmail のシステムラベル名セットです。
    /// </summary>
    private static readonly HashSet<string> GmailSystemLabelNameSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "CHAT",
        "SENT",
        "INBOX",
        "IMPORTANT",
        "TRASH",
        "DRAFT",
        "SPAM",
        "STARRED",
        "UNREAD",
        "CATEGORY_PERSONAL",
        "CATEGORY_SOCIAL",
        "CATEGORY_PROMOTIONS",
        "CATEGORY_UPDATES",
        "CATEGORY_FORUMS",
    };

    /// <summary>
    /// ラベル名一覧を labelIds に変換します。[251223_BVHM5V]
    /// </summary>
    /// <param name="httpClient">HTTP クライアントです。</param>
    /// <param name="accessToken">アクセストークンです。</param>
    /// <param name="labelNames">ラベル名一覧です。</param>
    /// <param name="cancel">キャンセル要求です。</param>
    /// <returns>labelIds 一覧です。</returns>
    private static async Task<List<string>> ResolveGmailLabelIdsAsync(HttpClient httpClient, string accessToken, List<string> labelNames, CancellationToken cancel)
    {
        if (httpClient == null) throw new ArgumentNullException(nameof(httpClient));
        if (accessToken == null) throw new ArgumentNullException(nameof(accessToken));

        if (labelNames == null || labelNames.Count == 0)
        {
            return new List<string>();
        }

        Dictionary<string, string> nameToIdMap;
        HashSet<string> idSet;

        (nameToIdMap, idSet) = await GetGmailLabelNameToIdMapAsync(httpClient, accessToken, cancel).ConfigureAwait(false);

        // 「/」区切りラベルは親から順に作成して階層構造を成立させる [251223_CTSHY7]
        List<string> hierarchyNames = BuildGmailLabelHierarchyList(labelNames);
        foreach (string rawName in hierarchyNames)
        {
            cancel.ThrowIfCancellationRequested();

            string name = (rawName ?? "").Trim();
            if (name.Length == 0) continue;

            if (IsGmailSystemLabelName(name)) continue;
            if (nameToIdMap.ContainsKey(name)) continue;
            if (idSet.Contains(name)) continue;

            try
            {
                string createdId = await CreateGmailLabelAsync(httpClient, accessToken, name, cancel).ConfigureAwait(false);
                nameToIdMap[name] = createdId;
                idSet.Add(createdId);
            }
            catch (Exception ex)
            {
                // 作成に失敗した場合は再取得して存在確認を行う
                (nameToIdMap, idSet) = await GetGmailLabelNameToIdMapAsync(httpClient, accessToken, cancel).ConfigureAwait(false);
                if (nameToIdMap.ContainsKey(name))
                {
                    continue;
                }

                throw new Exception(LibCommon.AppendExceptionDetail($"APPERROR: Failed to create Gmail label hierarchy: {name}", ex), ex);
            }
        }

        var labelIds = new List<string>();

        foreach (string rawName in labelNames)
        {
            cancel.ThrowIfCancellationRequested();

            string name = (rawName ?? "").Trim();
            if (name.Length == 0) continue;

            if (nameToIdMap.TryGetValue(name, out string? id))
            {
                labelIds.Add(id);
                continue;
            }

            // 既に labelIds が指定されているケースを許容する (ID の一致があればそのまま利用) [251223_BVHM5V]
            if (idSet.Contains(name))
            {
                labelIds.Add(name);
                continue;
            }

            if (IsGmailSystemLabelName(name))
            {
                labelIds.Add(name);
                continue;
            }

            throw new Exception($"APPERROR: Gmail label not found after creation: {name}");
        }

        return labelIds;
    }

    /// <summary>
    /// Gmail のラベル一覧を取得し、名前→ID の対応表を作成します。[251223_BVHM5V]
    /// </summary>
    /// <param name="httpClient">HTTP クライアントです。</param>
    /// <param name="accessToken">アクセストークンです。</param>
    /// <param name="cancel">キャンセル要求です。</param>
    /// <returns>名前→ID の対応表と ID セットです。</returns>
    private static async Task<(Dictionary<string, string> NameToIdMap, HashSet<string> IdSet)> GetGmailLabelNameToIdMapAsync(HttpClient httpClient, string accessToken, CancellationToken cancel)
    {
        if (httpClient == null) throw new ArgumentNullException(nameof(httpClient));
        if (accessToken == null) throw new ArgumentNullException(nameof(accessToken));

        const string Url = "https://gmail.googleapis.com/gmail/v1/users/me/labels";

        using var req = new HttpRequestMessage(HttpMethod.Get, Url);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        using HttpResponseMessage resp = await httpClient.SendAsync(req, cancel).ConfigureAwait(false);
        string body = await resp.Content.ReadAsStringAsync(cancel).ConfigureAwait(false);

        if (resp.IsSuccessStatusCode == false)
        {
            throw new Exception($"APPERROR: Gmail API users.labels.list returned {(int)resp.StatusCode} {resp.ReasonPhrase}. Body: {body}");
        }

        var nameToId = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var idSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            JObject root = JObject.Parse(body);
            if (root["labels"] is JArray labels)
            {
                foreach (var item in labels)
                {
                    string? id = item.Value<string>("id");
                    string? name = item.Value<string>("name");

                    if (string.IsNullOrWhiteSpace(id) == false)
                    {
                        id = id.Trim();
                        idSet.Add(id);
                    }

                    if (string.IsNullOrWhiteSpace(id) == false && string.IsNullOrWhiteSpace(name) == false)
                    {
                        nameToId[name!.Trim()] = id!;
                    }
                }
            }
        }
        catch (Exception ex)
        {
            throw new Exception(LibCommon.AppendExceptionDetail("APPERROR: Failed to parse Gmail labels.list response.", ex), ex);
        }

        return (nameToId, idSet);
    }

    /// <summary>
    /// Gmail に新しいラベルを作成します。[251223_BVHM5V]
    /// </summary>
    /// <param name="httpClient">HTTP クライアントです。</param>
    /// <param name="accessToken">アクセストークンです。</param>
    /// <param name="labelName">作成するラベル名です。</param>
    /// <param name="cancel">キャンセル要求です。</param>
    /// <returns>作成されたラベル ID です。</returns>
    private static async Task<string> CreateGmailLabelAsync(HttpClient httpClient, string accessToken, string labelName, CancellationToken cancel)
    {
        if (httpClient == null) throw new ArgumentNullException(nameof(httpClient));
        if (accessToken == null) throw new ArgumentNullException(nameof(accessToken));

        if (string.IsNullOrWhiteSpace(labelName))
        {
            throw new Exception("APPERROR: Gmail label name is empty.");
        }

        const string Url = "https://gmail.googleapis.com/gmail/v1/users/me/labels";

        string name = labelName.Trim();

        string json = JsonConvert.SerializeObject(new
        {
            name = name,
            labelListVisibility = "labelShow",
            messageListVisibility = "show",
        }, LibCommon.CreateStandardJsonSerializerSettings());
        json = json.Replace("\r\n", "\n").Replace("\r", "\n");

        using var req = new HttpRequestMessage(HttpMethod.Post, Url);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        req.Content = new StringContent(json, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false), "application/json");

        using HttpResponseMessage resp = await httpClient.SendAsync(req, cancel).ConfigureAwait(false);
        string body = await resp.Content.ReadAsStringAsync(cancel).ConfigureAwait(false);

        if (resp.IsSuccessStatusCode == false)
        {
            throw new Exception($"APPERROR: Gmail API users.labels.create returned {(int)resp.StatusCode} {resp.ReasonPhrase}. Body: {body}");
        }

        try
        {
            JObject root = JObject.Parse(body);
            string? id = root.Value<string>("id");
            if (string.IsNullOrWhiteSpace(id))
            {
                throw new Exception("APPERROR: Gmail API users.labels.create response does not contain id.");
            }
            return id.Trim();
        }
        catch (Exception ex)
        {
            throw new Exception(LibCommon.AppendExceptionDetail("APPERROR: Failed to parse Gmail labels.create response.", ex), ex);
        }
    }

    /// <summary>
    /// Gmail API の users.messages.import を呼び出します。
    /// </summary>
    /// <param name="config">設定です。</param>
    /// <param name="accessToken">アクセストークンです。</param>
    /// <param name="rawMail">メールの生データです。</param>
    /// <param name="meta">メールメタデータです。</param>
    /// <param name="filterResult">フィルタ結果です。</param>
    /// <param name="cancel">キャンセル要求です。</param>
    /// <returns>インポート結果種別です。</returns>
    private static async Task<GmailImportOutcome> GmailApiImportAsync(ForwardConfig config, string accessToken, byte[] rawMail, MailMetaData meta, MailForwardFilterResult filterResult, CancellationToken cancel)
    {
        if (config == null) throw new ArgumentNullException(nameof(config));
        if (accessToken == null) throw new ArgumentNullException(nameof(accessToken));
        if (rawMail == null) throw new ArgumentNullException(nameof(rawMail));
        if (meta == null) throw new ArgumentNullException(nameof(meta));
        if (filterResult == null) throw new ArgumentNullException(nameof(filterResult));

        using HttpClient httpClient = CreateHttpClientForGmail(config);

        string importMetaJson = await BuildGmailImportMetaJsonAsync(httpClient, accessToken, filterResult, cancel).ConfigureAwait(false);

        // まずは元メールのインポートを試みる
        GmailApiImportCallResult first = await GmailApiImportRawMessageWithRetriesAsync(httpClient, accessToken, rawMail, importMetaJson, config.Gmail.TcpRetryAttempts, cancel).ConfigureAwait(false);
        if (first.IsSuccess)
        {
            return GmailImportOutcome.ImportedOriginal;
        }

        // [ULP8TK5N] 400 Bad Request の場合のみ、添付削除の再試行を行う [GTFE562C]
        if (first.StatusCode != HttpStatusCode.BadRequest)
        {
            throw new Exception($"APPERROR: Gmail API users.messages.import returned {(int)first.StatusCode} {first.ReasonPhrase}. Body: {first.Body}");
        }

        // (a) 危険拡張子の添付ファイルを削除して再試行する [GTFE562C][LA5UBK7L]
        byte[]? stepA = TryBuildMailBytesForBadRequestStepA(rawMail);
        if (stepA != null)
        {
            GmailApiImportCallResult r = await GmailApiImportRawMessageWithRetriesAsync(httpClient, accessToken, stepA, importMetaJson, config.Gmail.TcpRetryAttempts, cancel).ConfigureAwait(false);
            if (r.IsSuccess) return GmailImportOutcome.ImportedAfterAttachmentRemovalStepA;
            if (r.StatusCode != HttpStatusCode.BadRequest)
            {
                throw new Exception($"APPERROR: Gmail API users.messages.import returned {(int)r.StatusCode} {r.ReasonPhrase}. Body: {r.Body}");
            }
        }

        // (b) 危険ファイルを含むアーカイブ添付を削除して再試行する [GTFE562C][LA5UBK7L]
        byte[]? stepB = TryBuildMailBytesForBadRequestStepB(rawMail);
        if (stepB != null)
        {
            GmailApiImportCallResult r = await GmailApiImportRawMessageWithRetriesAsync(httpClient, accessToken, stepB, importMetaJson, config.Gmail.TcpRetryAttempts, cancel).ConfigureAwait(false);
            if (r.IsSuccess) return GmailImportOutcome.ImportedAfterAttachmentRemovalStepB;
            if (r.StatusCode != HttpStatusCode.BadRequest)
            {
                throw new Exception($"APPERROR: Gmail API users.messages.import returned {(int)r.StatusCode} {r.ReasonPhrase}. Body: {r.Body}");
            }
        }

        // (c) すべての添付ファイルを削除して再試行する [GTFE562C]
        byte[]? stepC = TryBuildMailBytesForBadRequestStepC(rawMail);
        if (stepC != null)
        {
            GmailApiImportCallResult r = await GmailApiImportRawMessageWithRetriesAsync(httpClient, accessToken, stepC, importMetaJson, config.Gmail.TcpRetryAttempts, cancel).ConfigureAwait(false);
            if (r.IsSuccess) return GmailImportOutcome.ImportedAfterAttachmentRemovalStepC;
            if (r.StatusCode != HttpStatusCode.BadRequest)
            {
                throw new Exception($"APPERROR: Gmail API users.messages.import returned {(int)r.StatusCode} {r.ReasonPhrase}. Body: {r.Body}");
            }
        }

        // (a)(b)(c) いずれも 400 の場合は、代わりにシステムメッセージをインポートする [GTFE562C][HA7DHHGE]
        byte[] sysMsg = BuildSystemMessageRawMailBytes(config, meta, first.Body);

        try
        {
            GmailApiImportCallResult sysResp = await GmailApiImportRawMessageWithRetriesAsync(httpClient, accessToken, sysMsg, importMetaJson, config.Gmail.TcpRetryAttempts, cancel).ConfigureAwait(false);
            if (sysResp.IsSuccess)
            {
                return GmailImportOutcome.ImportedSystemMessageInstead;
            }

            throw new Exception($"APPERROR: Gmail API users.messages.import (system message) returned {(int)sysResp.StatusCode} {sysResp.ReasonPhrase}. Body: {sysResp.Body}");
        }
        catch (Exception ex)
        {
            // [HA7DHHGE] システムメッセージのインポート失敗はログ記録した上で元メールの失敗として扱う
            throw new Exception(LibCommon.AppendExceptionDetail("APPERROR: Failed to import system message to Gmail.", ex), ex);
        }
    }

    /// <summary>
    /// Gmail API import 呼び出し結果です。
    /// </summary>
    private sealed class GmailApiImportCallResult
    {
        /// <summary>
        /// 成功したかどうかです。
        /// </summary>
        public bool IsSuccess;

        /// <summary>
        /// HTTP ステータスコードです。(成功時は 200 系)
        /// </summary>
        public HttpStatusCode StatusCode;

        /// <summary>
        /// ReasonPhrase です。
        /// </summary>
        public string ReasonPhrase = "";

        /// <summary>
        /// レスポンスボディ文字列です。
        /// </summary>
        public string Body = "";
    }

    /// <summary>
    /// Gmail API users.messages.import を、通信エラー/5xx のリトライ付きで 1 回実行します。
    /// </summary>
    /// <param name="httpClient">HTTP クライアントです。</param>
    /// <param name="accessToken">アクセストークンです。</param>
    /// <param name="rawMail">メール生データです。</param>
    /// <param name="importMetaJson">インポート用メタデータ JSON です。</param>
    /// <param name="retryAttempts">最大リトライ回数です。</param>
    /// <param name="cancel">キャンセル要求です。</param>
    /// <returns>呼び出し結果です。</returns>
    private static async Task<GmailApiImportCallResult> GmailApiImportRawMessageWithRetriesAsync(HttpClient httpClient, string accessToken, byte[] rawMail, string importMetaJson, int retryAttempts, CancellationToken cancel)
    {
        if (httpClient == null) throw new ArgumentNullException(nameof(httpClient));
        if (accessToken == null) throw new ArgumentNullException(nameof(accessToken));
        if (rawMail == null) throw new ArgumentNullException(nameof(rawMail));
        if (importMetaJson == null) throw new ArgumentNullException(nameof(importMetaJson));
        if (retryAttempts <= 0) throw new ArgumentOutOfRangeException(nameof(retryAttempts));

        // ★ Gmail API users.messages.import は multipart upload を用いて、生メールデータを base64 変換せずに送信する
        //    これにより、サイズ増大 (base64 の 4/3) を回避し、(a) の生データをそのまま送れる。
        // ★ インポート時は neverMarkSpam=True を有効化する [N9YQARM8]
        const string Url = "https://gmail.googleapis.com/upload/gmail/v1/users/me/messages/import?uploadType=multipart&neverMarkSpam=true";

        HttpRequestException? lastHttpEx = null;

        for (int attempt = 1; attempt <= retryAttempts; attempt++)
        {
            cancel.ThrowIfCancellationRequested();

            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Post, Url);
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

                using var multipart = new MultipartContent("related");

                // part 1: JSON metadata
                var jsonPart = new StringContent(importMetaJson, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false), "application/json");
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
                    return new GmailApiImportCallResult
                    {
                        IsSuccess = true,
                        StatusCode = resp.StatusCode,
                        ReasonPhrase = resp.ReasonPhrase ?? "",
                        Body = body,
                    };
                }

                // 4xx は即失敗 (リトライしても意味が薄い) / 5xx はリトライ
                if ((int)resp.StatusCode >= 500 && attempt < retryAttempts)
                {
                    await Task.Delay(500, cancel).ConfigureAwait(false);
                    continue;
                }

                return new GmailApiImportCallResult
                {
                    IsSuccess = false,
                    StatusCode = resp.StatusCode,
                    ReasonPhrase = resp.ReasonPhrase ?? "",
                    Body = body,
                };
            }
            catch (HttpRequestException ex) when (attempt < retryAttempts)
            {
                lastHttpEx = ex;
                await Task.Delay(500, cancel).ConfigureAwait(false);
                continue;
            }
            catch (HttpRequestException ex)
            {
                throw new Exception(LibCommon.AppendExceptionDetail("APPERROR: Gmail API request failed.", ex), ex);
            }
        }

        throw new Exception(LibCommon.AppendExceptionDetail("APPERROR: Gmail API request failed after retries.", lastHttpEx), lastHttpEx);
    }

    /// <summary>
    /// Gmail が 400 Bad Request を応答した場合の、添付ファイル削除 (a) のメールデータを作成します。[GTFE562C]
    /// </summary>
    /// <param name="rawMail">元メールの生データです。</param>
    /// <returns>作成できた場合は新しいメール生データ、失敗した場合は null です。</returns>
    private static byte[]? TryBuildMailBytesForBadRequestStepA(byte[] rawMail)
    {
        if (rawMail == null) throw new ArgumentNullException(nameof(rawMail));

        MimeMessage message;
        try
        {
            using var ms = new MemoryStream(rawMail, writable: false);
            message = MimeMessage.Load(ms);
        }
        catch
        {
            return null;
        }

        try
        {
            var removeSet = new HashSet<MimeEntity>(ReferenceEqualityComparer<MimeEntity>.Instance);
            foreach (MimeEntity att in message.Attachments)
            {
                string fileName = GetMimeEntityFileNameBestEffort(att);
                if (HasDangerousFileExtension(fileName))
                {
                    removeSet.Add(att);
                }
            }

            RemoveAttachmentsFromMessage(message, removeSet);
            PrefixSubjectForAttachmentRemoval(message);

            return SerializeMimeMessageToBytes(message);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Gmail が 400 Bad Request を応答した場合の、添付ファイル削除 (b) のメールデータを作成します。[GTFE562C]
    /// </summary>
    /// <param name="rawMail">元メールの生データです。</param>
    /// <returns>作成できた場合は新しいメール生データ、失敗した場合は null です。</returns>
    private static byte[]? TryBuildMailBytesForBadRequestStepB(byte[] rawMail)
    {
        if (rawMail == null) throw new ArgumentNullException(nameof(rawMail));

        MimeMessage message;
        try
        {
            using var ms = new MemoryStream(rawMail, writable: false);
            message = MimeMessage.Load(ms);
        }
        catch
        {
            return null;
        }

        try
        {
            var removeSet = new HashSet<MimeEntity>(ReferenceEqualityComparer<MimeEntity>.Instance);

            foreach (MimeEntity att in message.Attachments)
            {
                string fileName = GetMimeEntityFileNameBestEffort(att);
                if (IsArchiveFileName(fileName) == false)
                {
                    continue;
                }

                if (TryGetDecodedMimeEntityBytes(att, out byte[] attBytes) == false)
                {
                    // 解析できないアーカイブは疑わしいため削除対象とする (ベストエフォート) [GTFE562C]
                    removeSet.Add(att);
                    continue;
                }

                if (ArchiveContainsDangerousFileName(fileName, attBytes, out _))
                {
                    removeSet.Add(att);
                }
            }

            RemoveAttachmentsFromMessage(message, removeSet);
            PrefixSubjectForAttachmentRemoval(message);

            return SerializeMimeMessageToBytes(message);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Gmail が 400 Bad Request を応答した場合の、添付ファイル削除 (c) のメールデータを作成します。[GTFE562C]
    /// </summary>
    /// <param name="rawMail">元メールの生データです。</param>
    /// <returns>作成できた場合は新しいメール生データ、失敗した場合は null です。</returns>
    private static byte[]? TryBuildMailBytesForBadRequestStepC(byte[] rawMail)
    {
        if (rawMail == null) throw new ArgumentNullException(nameof(rawMail));

        MimeMessage message;
        try
        {
            using var ms = new MemoryStream(rawMail, writable: false);
            message = MimeMessage.Load(ms);
        }
        catch
        {
            return null;
        }

        try
        {
            var removeSet = new HashSet<MimeEntity>(ReferenceEqualityComparer<MimeEntity>.Instance);
            foreach (MimeEntity att in message.Attachments)
            {
                removeSet.Add(att);
            }

            RemoveAttachmentsFromMessage(message, removeSet);
            PrefixSubjectForAttachmentRemoval(message);

            return SerializeMimeMessageToBytes(message);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// 添付ファイル削除時の Subject プレフィックスを付与します。[GTFE562C]
    /// </summary>
    /// <param name="message">MimeMessage です。</param>
    private static void PrefixSubjectForAttachmentRemoval(MimeMessage message)
    {
        if (message == null) throw new ArgumentNullException(nameof(message));

        string original = message.Subject ?? "";
        message.Subject = $"【注: 転送時に添付ファイル削除】 {original}";
    }

    /// <summary>
    /// MimeMessage から指定された添付ファイル群を削除します。
    /// </summary>
    /// <param name="message">MimeMessage です。</param>
    /// <param name="removeSet">削除対象の MimeEntity セットです。</param>
    private static void RemoveAttachmentsFromMessage(MimeMessage message, HashSet<MimeEntity> removeSet)
    {
        if (message == null) throw new ArgumentNullException(nameof(message));
        if (removeSet == null) throw new ArgumentNullException(nameof(removeSet));

        if (message.Body == null)
        {
            message.Body = new TextPart("plain") { Text = "" };
            return;
        }

        // ルートが削除対象の場合はプレースホルダに置換する
        if (removeSet.Contains(message.Body))
        {
            message.Body = new TextPart("plain") { Text = "" };
            return;
        }

        RemoveMimeEntitiesInPlace(message.Body, removeSet);

        if (message.Body is Multipart mp && mp.Count == 0)
        {
            mp.Add(new TextPart("plain") { Text = "" });
        }
    }

    private static int RemoveMimeEntitiesInPlace(MimeEntity entity, HashSet<MimeEntity> removeSet)
    {
        if (entity == null) throw new ArgumentNullException(nameof(entity));
        if (removeSet == null) throw new ArgumentNullException(nameof(removeSet));

        int removed = 0;

        if (entity is Multipart multipart)
        {
            for (int i = multipart.Count - 1; i >= 0; i--)
            {
                MimeEntity child = multipart[i];

                if (removeSet.Contains(child))
                {
                    multipart.RemoveAt(i);
                    removed++;
                    continue;
                }

                removed += RemoveMimeEntitiesInPlace(child, removeSet);

                if (child is Multipart childMp && childMp.Count == 0)
                {
                    multipart[i] = new TextPart("plain") { Text = "" };
                }
            }
        }

        return removed;
    }

    /// <summary>
    /// MimeEntity のファイル名を、可能な範囲で取得します。
    /// </summary>
    /// <param name="entity">MimeEntity です。</param>
    /// <returns>ファイル名です。無い場合は "" です。</returns>
    private static string GetMimeEntityFileNameBestEffort(MimeEntity entity)
    {
        if (entity == null) throw new ArgumentNullException(nameof(entity));

        try
        {
            if (entity is MimePart part)
            {
                string? f = part.FileName;
                if (string.IsNullOrWhiteSpace(f) == false) return f.Trim();
            }
        }
        catch { }

        try
        {
            string? f = entity.ContentDisposition?.FileName;
            if (string.IsNullOrWhiteSpace(f) == false) return f.Trim();
        }
        catch { }

        try
        {
            string? f = entity.ContentType?.Name;
            if (string.IsNullOrWhiteSpace(f) == false) return f.Trim();
        }
        catch { }

        return "";
    }

    /// <summary>
    /// 添付ファイルのバイナリ内容を (Content-Transfer-Encoding をデコードした上で) 取得します。
    /// </summary>
    /// <param name="entity">MimeEntity です。</param>
    /// <param name="bytes">出力バイト列です。</param>
    /// <returns>取得できた場合は true です。</returns>
    private static bool TryGetDecodedMimeEntityBytes(MimeEntity entity, out byte[] bytes)
    {
        if (entity == null) throw new ArgumentNullException(nameof(entity));

        bytes = Array.Empty<byte>();

        try
        {
            if (entity is MimePart part)
            {
                if (part.Content == null) return false;
                using var ms = new MemoryStream();
                part.Content.DecodeTo(ms);
                bytes = ms.ToArray();
                return true;
            }
        }
        catch
        {
            return false;
        }

        try
        {
            if (entity is MessagePart msgPart && msgPart.Message != null)
            {
                bytes = SerializeMimeMessageToBytes(msgPart.Message);
                return true;
            }
        }
        catch
        {
            return false;
        }

        return false;
    }

    /// <summary>
    /// MimeMessage を RFC822 形式のバイト列にシリアライズします。
    /// </summary>
    /// <param name="message">MimeMessage です。</param>
    /// <returns>生メールバイト列です。</returns>
    private static byte[] SerializeMimeMessageToBytes(MimeMessage message)
    {
        if (message == null) throw new ArgumentNullException(nameof(message));

        using var ms = new MemoryStream();
        message.WriteTo(ms);
        return ms.ToArray();
    }

    /// <summary>
    /// 危険な拡張子を持つファイルかどうかを判定します。[LA5UBK7L]
    /// </summary>
    /// <param name="fileName">ファイル名です。</param>
    /// <returns>危険と判定した場合は true です。</returns>
    private static bool HasDangerousFileExtension(string fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName)) return false;

        string s = fileName.Trim().Replace('\\', '/');
        int slash = s.LastIndexOf('/');
        if (slash >= 0 && slash + 1 < s.Length) s = s.Substring(slash + 1);
        s = s.Trim().ToLowerInvariant();

        foreach (string ext in DangerousFileExtensions_LA5UBK7L)
        {
            if (s.EndsWith(ext, StringComparison.Ordinal) ||
                s.EndsWith(ext + ".gz", StringComparison.Ordinal) ||
                s.EndsWith(ext + ".bz2", StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// アーカイブ添付ファイル名かどうかを判定します。[GTFE562C]
    /// </summary>
    /// <param name="fileName">ファイル名です。</param>
    /// <returns>アーカイブと判定した場合は true です。</returns>
    private static bool IsArchiveFileName(string fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName)) return false;
        string s = fileName.Trim().ToLowerInvariant();

        return s.EndsWith(".zip", StringComparison.Ordinal) ||
               s.EndsWith(".tar.gz", StringComparison.Ordinal) ||
               s.EndsWith(".tgz", StringComparison.Ordinal) ||
               s.EndsWith(".tar", StringComparison.Ordinal);
    }

    /// <summary>
    /// アーカイブ内に危険拡張子ファイル名が含まれているか確認します。[GTFE562C][LA5UBK7L]
    /// </summary>
    /// <param name="archiveFileName">アーカイブファイル名です。</param>
    /// <param name="archiveBytes">アーカイブ本体バイト列です。</param>
    /// <param name="foundEntryName">見つかったエントリ名です。</param>
    /// <returns>含まれている場合は true です。</returns>
    private static bool ArchiveContainsDangerousFileName(string archiveFileName, byte[] archiveBytes, out string foundEntryName)
    {
        if (archiveFileName == null) throw new ArgumentNullException(nameof(archiveFileName));
        if (archiveBytes == null) throw new ArgumentNullException(nameof(archiveBytes));

        foundEntryName = "";

        string s = archiveFileName.Trim().ToLowerInvariant();

        try
        {
            if (s.EndsWith(".zip", StringComparison.Ordinal))
            {
                using var ms = new MemoryStream(archiveBytes, writable: false);
                using var zip = new ZipArchive(ms, ZipArchiveMode.Read, leaveOpen: false);
                foreach (var entry in zip.Entries)
                {
                    string name = entry.FullName ?? "";
                    if (HasDangerousFileExtension(name))
                    {
                        foundEntryName = name;
                        return true;
                    }
                }

                return false;
            }

            if (s.EndsWith(".tar", StringComparison.Ordinal))
            {
                using var ms = new MemoryStream(archiveBytes, writable: false);
                return TarContainsDangerousFileName(ms, out foundEntryName);
            }

            if (s.EndsWith(".tgz", StringComparison.Ordinal) || s.EndsWith(".tar.gz", StringComparison.Ordinal))
            {
                using var ms = new MemoryStream(archiveBytes, writable: false);
                using var gz = new GZipStream(ms, CompressionMode.Decompress, leaveOpen: false);
                return TarContainsDangerousFileName(gz, out foundEntryName);
            }
        }
        catch
        {
            // パース不能な場合は「危険なし」とみなす (ベストエフォート)
            foundEntryName = "";
            return false;
        }

        return false;
    }

    /// <summary>
    /// tar ストリーム内に危険拡張子ファイル名が含まれているか確認します。[GTFE562C][LA5UBK7L]
    /// </summary>
    /// <param name="tarStream">tar ストリームです。</param>
    /// <param name="foundEntryName">見つかったエントリ名です。</param>
    /// <returns>含まれている場合は true です。</returns>
    private static bool TarContainsDangerousFileName(Stream tarStream, out string foundEntryName)
    {
        if (tarStream == null) throw new ArgumentNullException(nameof(tarStream));

        foundEntryName = "";

        byte[] header = new byte[512];

        while (true)
        {
            if (ReadExactlyOrEof(tarStream, header, 0, header.Length) == false)
            {
                return false;
            }

            if (IsAllZero(header))
            {
                // 終端 (512 bytes x2 だが、最初の 1 ブロックで十分)
                return false;
            }

            string name = ReadNullTerminatedAscii(header, 0, 100);
            string prefix = ReadNullTerminatedAscii(header, 345, 155);
            if (string.IsNullOrEmpty(prefix) == false)
            {
                name = prefix + "/" + name;
            }

            if (HasDangerousFileExtension(name))
            {
                foundEntryName = name;
                return true;
            }

            long size = ParseTarOctal(header, 124, 12);
            long skip = ((size + 511) / 512) * 512;
            if (skip > 0)
            {
                SkipExactly(tarStream, skip);
            }
        }
    }

    private static bool ReadExactlyOrEof(Stream s, byte[] buf, int offset, int count)
    {
        int total = 0;
        while (total < count)
        {
            int r = s.Read(buf, offset + total, count - total);
            if (r <= 0)
            {
                return false;
            }
            total += r;
        }
        return true;
    }

    private static void SkipExactly(Stream s, long count)
    {
        if (count <= 0) return;

        byte[] tmp = ArrayPool<byte>.Shared.Rent(8192);
        try
        {
            long remaining = count;
            while (remaining > 0)
            {
                int toRead = (int)Math.Min(tmp.Length, remaining);
                int r = s.Read(tmp, 0, toRead);
                if (r <= 0)
                {
                    throw new EndOfStreamException("APPERROR: Unexpected end of tar stream.");
                }
                remaining -= r;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(tmp);
        }
    }

    private static bool IsAllZero(byte[] buf)
    {
        foreach (byte b in buf)
        {
            if (b != 0) return false;
        }
        return true;
    }

    private static string ReadNullTerminatedAscii(byte[] buf, int offset, int len)
    {
        int end = offset;
        int max = offset + len;
        while (end < max && buf[end] != 0) end++;

        return Encoding.ASCII.GetString(buf, offset, end - offset).Trim();
    }

    private static long ParseTarOctal(byte[] buf, int offset, int len)
    {
        long n = 0;
        int end = offset + len;

        for (int i = offset; i < end; i++)
        {
            byte b = buf[i];
            if (b == 0 || b == (byte)' ' || b == (byte)'\t') continue;
            if (b < (byte)'0' || b > (byte)'7') break;

            n = (n << 3) + (b - (byte)'0');
        }

        return n;
    }

    /// <summary>
    /// 400 Bad Request 時のシステムメッセージを作成します。[GTFE562C][HA7DHHGE]
    /// </summary>
    /// <param name="config">設定です。</param>
    /// <param name="meta">元メールのメタデータです。</param>
    /// <param name="errorMessage">Gmail API からのエラー応答文字列です。</param>
    /// <returns>システムメッセージの生メールデータです。</returns>
    private static byte[] BuildSystemMessageRawMailBytes(ForwardConfig config, MailMetaData meta, string errorMessage)
    {
        if (config == null) throw new ArgumentNullException(nameof(config));
        if (meta == null) throw new ArgumentNullException(nameof(meta));
        if (errorMessage == null) errorMessage = "";

        MailboxAddress sysMailbox;
        try
        {
            sysMailbox = MailboxAddress.Parse(config.Gmail.GmailSystemMessageMailAddress);
        }
        catch (Exception ex)
        {
            throw new Exception(LibCommon.AppendExceptionDetail("APPERROR: Invalid gmail.gmail_system_message_mail_address.", ex), ex);
        }

        string fromStr = meta.AddressList_From?.ToString() ?? "";
        string subjectInner = $"【メール転送インポート失敗】: Subject: {meta.Subject} (From: {fromStr})";

        string dtHeader = meta.DateTime_Header?.ToString("yyyy/MM/dd HH:mm:ss zzz", CultureInfo.InvariantCulture) ?? "";
        string toStr = string.Join(", ", meta.AddressList_To.Select(x => x.ToString()));
        string ccStr = string.Join(", ", meta.AddressList_Cc.Select(x => x.ToString()));

        string body =
            "以下のメールを Gmail API を用いて転送インポートしようとしたところ、\n" +
            $"エラーメッセージ「{errorMessage}」が発生しました。\n" +
            "\n" +
            $"メールのサイズ: {meta.MailSize} バイト\n" +
            $"メールの Subject: {meta.Subject}\n" +
            $"メールの日時: {dtHeader}\n" +
            $"メールの From: {fromStr}\n" +
            $"メールの To: {toStr}\n" +
            $"メールの Cc: {ccStr}\n" +
            $"メールの添付ファイルの数: {meta.AttachmentFileNamesList.Count} 個\n";

        var msg = new MimeMessage();
        msg.Date = DateTimeOffset.Now;
        msg.From.Add(sysMailbox);
        msg.To.Add(sysMailbox);
        msg.MessageId = CreateRandomMessageId(sysMailbox.Address);
        msg.Subject = "sysmsg " + subjectInner;

        // Return-Path を明示する [HA7DHHGE]
        try
        {
            msg.Headers.Replace(HeaderId.ReturnPath, $"<{sysMailbox.Address}>");
        }
        catch { }

        msg.Body = new TextPart("plain")
        {
            Text = body,
        };

        return SerializeMimeMessageToBytes(msg);
    }

    private static string CreateRandomMessageId(string mailAddress)
    {
        if (mailAddress == null) mailAddress = "";

        string domain = "localhost";
        int at = mailAddress.IndexOf('@');
        if (at >= 0 && at + 1 < mailAddress.Length)
        {
            string d = mailAddress.Substring(at + 1).Trim();
            if (string.IsNullOrWhiteSpace(d) == false)
            {
                domain = d;
            }
        }

        string id = Guid.NewGuid().ToString("N");
        return $"<{id}@{domain}>";
    }

    /// <summary>
    /// 危険な拡張子のリストです。[LA5UBK7L]
    /// </summary>
    private static readonly HashSet<string> DangerousFileExtensions_LA5UBK7L = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        ".ade", ".adp", ".apk", ".appx", ".appxbundle", ".bat", ".cab", ".chm", ".cmd", ".com", ".cpl", ".diagcab", ".diagcfg", ".diagpkg",
        ".dll", ".dmg", ".ex", ".ex_", ".exe", ".hta", ".img", ".ins", ".iso", ".isp", ".jar", ".jnlp", ".js", ".jse", ".lib", ".lnk",
        ".mde", ".mjs", ".msc", ".msi", ".msix", ".msixbundle", ".msp", ".mst", ".nsh", ".pif", ".ps1", ".scr", ".sct", ".shb", ".sys",
        ".vb", ".vbe", ".vbs", ".vhd", ".vxd", ".wsc", ".wsf", ".wsh", ".xll",
    };

    /// <summary>
    /// 参照等価性で比較するためのコンパレータです。
    /// </summary>
    private sealed class ReferenceEqualityComparer<T> : IEqualityComparer<T> where T : class
    {
        public static readonly ReferenceEqualityComparer<T> Instance = new ReferenceEqualityComparer<T>();

        public bool Equals(T? x, T? y) => ReferenceEquals(x, y);

        public int GetHashCode(T obj) => RuntimeHelpers.GetHashCode(obj);
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
        bool hasTarPassDays = TryGetOptionalInt(model, "generic", "archive_enable_tar_pass_days", out int tarPassDays);

        cfg.Generic = new GenericConfig
        {
            ArchiveDir = ResolveConfigPath(configDir, GetRequiredString(model, "generic", "archive_dir")),
            ArchiveEnableGzip = GetOptionalBool(model, "generic", "archive_enable_gzip", false),
            ArchiveEnableTar = GetOptionalBool(model, "generic", "archive_enable_tar", false),
            ArchiveEnableTarPassDays = hasTarPassDays ? tarPassDays : 0,
            LogDir = ResolveConfigPath(configDir, GetRequiredString(model, "generic", "log_dir")),
            StatFileName = ResolveConfigPath(configDir, GetRequiredString(model, "generic", "stat_filename")),
        };

        // archive_enable_tar_pass_days は archive_enable_tar = true の場合必須かつ 1 以上 [251224_VMWE23]
        if (cfg.Generic.ArchiveEnableTar)
        {
            if (hasTarPassDays == false)
            {
                throw new Exception("APPERROR: Missing TOML value: generic.archive_enable_tar_pass_days");
            }

            if (cfg.Generic.ArchiveEnableTarPassDays < 1)
            {
                throw new Exception($"APPERROR: TOML integer out of range (1..): generic.archive_enable_tar_pass_days = {cfg.Generic.ArchiveEnableTarPassDays}");
            }
        }
        else
        {
            if (hasTarPassDays && cfg.Generic.ArchiveEnableTarPassDays < 0)
            {
                throw new Exception($"APPERROR: TOML integer out of range (0..): generic.archive_enable_tar_pass_days = {cfg.Generic.ArchiveEnableTarPassDays}");
            }
        }

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
            GmailSystemMessageMailAddress = GetRequiredString(model, "gmail", "gmail_system_message_mail_address"),
        };

        // gmail_system_message_mail_address の妥当性検証 (MimeKit でパース可能であること) [HA7DHHGE]
        try
        {
            _ = MailboxAddress.Parse(cfg.Gmail.GmailSystemMessageMailAddress);
        }
        catch (Exception ex)
        {
            throw new Exception(LibCommon.AppendExceptionDetail("APPERROR: Invalid TOML value: gmail.gmail_system_message_mail_address", ex), ex);
        }

        // filter
        string filterFileName = GetOptionalString(model, "filter", "filter_csharp_filename");
        string filterFilePath = "";
        string filterSource = "";

        if (string.IsNullOrWhiteSpace(filterFileName) == false)
        {
            filterFilePath = ResolveConfigPath(configDir, filterFileName);

            if (File.Exists(filterFilePath) == false)
            {
                throw new Exception($"APPERROR: filter_csharp_filename file not found: {filterFilePath}");
            }

            filterSource = await File.ReadAllTextAsync(filterFilePath, cancel).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(filterSource))
            {
                throw new Exception($"APPERROR: filter_csharp_filename file is empty: {filterFilePath}");
            }
        }

        cfg.Filter = new FilterConfig
        {
            FilterCSharpFilePath = filterFilePath,
            FilterSourceCode = filterSource,
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
    /// TOML の任意 int フィールドを取得します。(存在しない場合は false)
    /// </summary>
    /// <param name="root">ルートテーブルです。</param>
    /// <param name="tableName">テーブル名です。</param>
    /// <param name="key">キー名です。</param>
    /// <param name="value">取得した値です。</param>
    /// <returns>存在した場合は true です。</returns>
    private static bool TryGetOptionalInt(TomlTable root, string tableName, string key, out int value)
    {
        if (root == null) throw new ArgumentNullException(nameof(root));
        if (tableName == null) throw new ArgumentNullException(nameof(tableName));
        if (key == null) throw new ArgumentNullException(nameof(key));

        value = 0;

        if (root.TryGetValue(tableName, out object? tableObj) == false || tableObj is TomlTable table == false)
        {
            return false;
        }

        if (table.TryGetValue(key, out object? valueObj) == false || valueObj == null)
        {
            return false;
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

        if (n < int.MinValue || n > int.MaxValue)
        {
            throw new Exception($"APPERROR: TOML integer out of range ({int.MinValue}..{int.MaxValue}): {tableName}.{key} = {n}");
        }

        value = (int)n;
        return true;
    }

    /// <summary>
    /// TOML の任意 bool フィールドを取得します。(無い場合は既定値を返します)
    /// </summary>
    /// <param name="root">ルートテーブルです。</param>
    /// <param name="tableName">テーブル名です。</param>
    /// <param name="key">キー名です。</param>
    /// <param name="defaultValue">既定値です。</param>
    /// <returns>bool 値です。</returns>
    private static bool GetOptionalBool(TomlTable root, string tableName, string key, bool defaultValue)
    {
        if (root == null) throw new ArgumentNullException(nameof(root));
        if (tableName == null) throw new ArgumentNullException(nameof(tableName));
        if (key == null) throw new ArgumentNullException(nameof(key));

        if (root.TryGetValue(tableName, out object? tableObj) == false || tableObj is TomlTable table == false)
        {
            return defaultValue;
        }

        if (table.TryGetValue(key, out object? valueObj) == false || valueObj == null)
        {
            return defaultValue;
        }

        if (valueObj is bool b)
        {
            return b;
        }

        throw new Exception($"APPERROR: TOML value type must be bool: {tableName}.{key}");
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

        /// <summary>
        /// filter セクションです。
        /// </summary>
        public FilterConfig Filter = new FilterConfig();
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
        /// アーカイブ保存時に gzip 圧縮を有効にするかどうかです。
        /// </summary>
        public bool ArchiveEnableGzip;

        /// <summary>
        /// アーカイブディレクトリの自動 tar 化を有効にするかどうかです。
        /// </summary>
        public bool ArchiveEnableTar;

        /// <summary>
        /// 自動 tar 化の経過日数条件です。
        /// </summary>
        public int ArchiveEnableTarPassDays;

        /// <summary>
        /// ログディレクトリです。(フルパス)
        /// </summary>
        public string LogDir = "";

        /// <summary>
        /// 統計情報ファイル名です。(フルパス)
        /// </summary>
        public string StatFileName = "";
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

        /// <summary>
        /// システムメッセージの仮想メールアドレスです。[A44FBNFX][HA7DHHGE]
        /// </summary>
        public string GmailSystemMessageMailAddress = "";
    }

    /// <summary>
    /// filter 設定です。[251222_ZXH7N7]
    /// </summary>
    private sealed class FilterConfig
    {
        /// <summary>
        /// ユーザーフィルタ C# ソースコードのファイルパスです。(フルパス)
        /// </summary>
        public string FilterCSharpFilePath = "";

        /// <summary>
        /// ユーザーフィルタ C# ソースコード本文です。未指定の場合は空文字です。
        /// </summary>
        public string FilterSourceCode = "";
    }

    /// <summary>
    /// forward モードのログ出力実装です。[Y5CRNZA3]
    /// </summary>
    private sealed class ForwardLogger
    {
        private readonly string _logDir;
        private long _errorCount;
        // ループモード向けの 1 サイクル内エラーカウントです。
        private long _loopErrorCount;

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
        /// 統計用のエラー件数を取得し、カウントをリセットします。
        /// </summary>
        /// <returns>リセット前のエラー件数です。</returns>
        public long ConsumeErrorCount()
        {
            return Interlocked.Exchange(ref _errorCount, 0);
        }

        /// <summary>
        /// ループモード向けのエラーカウントを取得し、リセットします。
        /// </summary>
        /// <returns>リセット前のエラーカウントです。</returns>
        public long ConsumeLoopErrorCount()
        {
            return Interlocked.Exchange(ref _loopErrorCount, 0);
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

            if (isError)
            {
                Interlocked.Increment(ref _errorCount);
                Interlocked.Increment(ref _loopErrorCount);
            }

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

                string fileName = DateTimeOffset.Now.ToLocalTime().ToString("yyyyMMdd", CultureInfo.InvariantCulture) + ".log";
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
        /// LIST を取得します。[WZZM4P46]
        /// </summary>
        /// <param name="cancel">キャンセル要求です。</param>
        /// <returns>メール一覧です。(セッション内でユニークな MessageNo とサイズ)</returns>
        public async Task<List<Pop3MessageListItem>> ListAsync(CancellationToken cancel)
        {
            await SendCommandAsync("LIST", cancel).ConfigureAwait(false);
            string first = await ReadLineAsync(cancel).ConfigureAwait(false);
            EnsureOk(first);

            var list = new List<Pop3MessageListItem>();

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

                string[] parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2 &&
                    int.TryParse(parts[0], NumberStyles.Integer, CultureInfo.InvariantCulture, out int messageNo) &&
                    int.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out int mailSize))
                {
                    list.Add(new Pop3MessageListItem
                    {
                        MessageNo = messageNo,
                        MailSize = mailSize,
                    });
                }
                else
                {
                    throw new Exception($"APPERROR: Invalid LIST response line: {line}");
                }
            }

            return list;
        }

        /// <summary>
        /// POP3 LIST の 1 行分データです。[WZZM4P46][KHQN6UTY]
        /// </summary>
        public sealed class Pop3MessageListItem
        {
            /// <summary>
            /// メッセージ番号です。(セッション内でユニーク) [KHQN6UTY]
            /// </summary>
            public int MessageNo;

            /// <summary>
            /// メッセージサイズ (バイト) です。
            /// </summary>
            public int MailSize;
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

    public string GetBodyAll()
    {
        return PlainTextBody + " " + HtmlBody;
    }

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
