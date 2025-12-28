// Author: Daiyuu Nobori
// Created: 2025-12-28
// Powered by AI: GPT-5 (Codex CLI)

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
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace dn_pop3_to_gmail_forwarder;

/// <summary>
/// loop モード [251228_RYJXF4] の機能実装です。
/// </summary>
public static class FeatureLoop
{
    /// <summary>
    /// loop モードの実行パラメータです。
    /// </summary>
    public sealed class LoopOptions
    {
        /// <summary>
        /// loop モード用の TOML 設定ファイルパスです。
        /// </summary>
        public string ConfigPath = "";
    }

    /// <summary>
    /// loop モードを実行します。
    /// </summary>
    /// <param name="options">実行パラメータです。</param>
    /// <param name="cancel">キャンセル要求です。</param>
    /// <returns>プロセス戻り値です。(0: 成功 / 1: 失敗)</returns>
    public static async Task<int> RunAsync(LoopOptions options, CancellationToken cancel = default)
    {
        if (options == null) throw new ArgumentNullException(nameof(options));

        return await FeatureForward.RunLoopAsync(options.ConfigPath, cancel).ConfigureAwait(false);
    }
}

#endif
