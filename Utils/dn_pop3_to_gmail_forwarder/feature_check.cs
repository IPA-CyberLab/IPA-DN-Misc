// Author: Daiyuu Nobori
// Created: 2025-12-23
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
/// check モード [251222_ZYMQ4U] の機能実装です。
/// </summary>
public static class FeatureCheck
{
    /// <summary>
    /// check モードの実行パラメータです。
    /// </summary>
    public sealed class CheckOptions
    {
        /// <summary>
        /// check モード用の TOML 設定ファイルパスです。
        /// </summary>
        public string ConfigPath = "";
    }

    /// <summary>
    /// check モードを実行します。
    /// </summary>
    /// <param name="options">実行パラメータです。</param>
    /// <param name="cancel">キャンセル要求です。</param>
    /// <returns>プロセス戻り値です。(0: 成功 / 1: 失敗)</returns>
    public static async Task<int> RunAsync(CheckOptions options, CancellationToken cancel = default)
    {
        if (options == null) throw new ArgumentNullException(nameof(options));

        return await FeatureForward.RunCheckAsync(options.ConfigPath, cancel).ConfigureAwait(false);
    }
}

#endif
