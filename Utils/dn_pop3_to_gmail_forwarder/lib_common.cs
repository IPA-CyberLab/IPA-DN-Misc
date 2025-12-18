// Author: Daiyuu Nobori
// Created: 2025-12-18
// Powered by AI: GPT-5.2

#if true

#pragma warning disable CA2235 // Mark all non-serializable fields

using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace dn_pop3_to_gmail_forwarder;

/// <summary>
/// 共通的なユーティリティ処理群です。 [E64UYSSZ]
/// </summary>
public static class LibCommon
{
    /// <summary>
    /// Newtonsoft.Json 用の標準シリアライズ設定を作成します。 [PV4U3JTR]
    /// </summary>
    /// <returns>シリアライズ設定です。</returns>
    public static JsonSerializerSettings CreateStandardJsonSerializerSettings()
    {
        return new JsonSerializerSettings
        {
            MaxDepth = 8,
            NullValueHandling = NullValueHandling.Ignore,
            ReferenceLoopHandling = ReferenceLoopHandling.Error,
            PreserveReferencesHandling = PreserveReferencesHandling.None,
            StringEscapeHandling = StringEscapeHandling.Default,
            Formatting = Formatting.Indented,
        };
    }

    /// <summary>
    /// JSON を単一の設定ファイルとして書き出すための文字列を生成します。(改行は LF のみ) [PV4U3JTR]
    /// </summary>
    /// <param name="data">シリアライズ対象オブジェクトです。</param>
    /// <returns>ファイルに保存する文字列です。(先頭 2 行改行 + JSON + 末尾 3 行改行)</returns>
    public static string BuildSingleJsonFileText(object data)
    {
        if (data == null) throw new ArgumentNullException(nameof(data));

        string jsonBody = JsonConvert.SerializeObject(data, CreateStandardJsonSerializerSettings());
        jsonBody = NormalizeNewlinesToLf(jsonBody);
        jsonBody = jsonBody.TrimEnd('\n');

        // ★ JSON ファイルの書式規約: 先頭に 2 行改行、末尾に 3 行改行を付与する [PV4U3JTR]
        return "\n\n" + jsonBody + "\n\n\n";
    }

    /// <summary>
    /// JSON を単一の設定ファイルとして、テンポラリ経由で安全に書き出します。(UTF-8 BOM 付き) [PV4U3JTR]
    /// </summary>
    /// <param name="path">保存先ファイルパスです。</param>
    /// <param name="data">保存する JSON データです。</param>
    /// <param name="cancel">キャンセル要求です。</param>
    /// <returns>完了タスクです。</returns>
    public static async Task WriteSingleJsonFileByTempAsync(string path, object data, CancellationToken cancel = default)
    {
        if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException("APPERROR: path is empty.", nameof(path));
        if (data == null) throw new ArgumentNullException(nameof(data));

        string? dir = Path.GetDirectoryName(path);
        if (string.IsNullOrEmpty(dir) == false)
        {
            Directory.CreateDirectory(dir);
        }

        string tmpPath = path + ".tmp_" + Guid.NewGuid().ToString("N");

        string text = BuildSingleJsonFileText(data);

        // ★ JSON ファイルは UTF-8 BOM を付与する [PV4U3JTR]
        await File.WriteAllTextAsync(tmpPath, text, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true), cancel).ConfigureAwait(false);

        File.Move(tmpPath, path, overwrite: true);
    }

    /// <summary>
    /// JSON を単一の設定ファイルとして読み出し、デシリアライズします。(UTF-8 BOM 有無両対応) [PV4U3JTR]
    /// </summary>
    /// <typeparam name="T">デシリアライズ先の型です。</typeparam>
    /// <param name="path">読み込み元ファイルパスです。</param>
    /// <param name="cancel">キャンセル要求です。</param>
    /// <returns>読み出したデータです。</returns>
    public static async Task<T> ReadSingleJsonFileAsync<T>(string path, CancellationToken cancel = default)
    {
        if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException("APPERROR: path is empty.", nameof(path));

        string text = await File.ReadAllTextAsync(path, cancel).ConfigureAwait(false);

        // ★ BOM 有無両対応 (念のため U+FEFF も明示的に除去する) [PV4U3JTR]
        if (text.Length >= 1 && text[0] == '\uFEFF')
        {
            text = text.Substring(1);
        }

        text = text.Trim();

        T? obj = JsonConvert.DeserializeObject<T>(text, CreateStandardJsonSerializerSettings());
        if (obj == null)
        {
            throw new Exception("APPERROR: JSON deserialize returned null.");
        }

        return obj;
    }

    /// <summary>
    /// 文字列の改行コードを、CR / CRLF を含む可能性から、LF のみに正規化します。 [PV4U3JTR]
    /// </summary>
    /// <param name="src">入力文字列です。</param>
    /// <returns>改行が LF のみに統一された文字列です。</returns>
    private static string NormalizeNewlinesToLf(string src)
    {
        if (src == null) throw new ArgumentNullException(nameof(src));

        if (src.IndexOf('\r') == -1) return src;

        // CRLF -> LF の順で置換することで、CRLF が LF + LF にならないようにする
        return src.Replace("\r\n", "\n").Replace("\r", "\n");
    }
}

#endif

