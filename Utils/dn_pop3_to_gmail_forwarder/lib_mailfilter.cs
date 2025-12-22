using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.Loader;
using System.Security.Cryptography;
using System.Text;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Emit;

namespace dn_pop3_to_gmail_forwarder;

public class MailForwardFilterParam
{
    // 対象メールのメタデータ
    public MailMetaData Mail = null!;
}

public class MailForwardFilterResult
{
    public bool MarkAsRead; // Gmail に転送 (インポート) する際、[UNREAD] フラグを付けない。
    public HashSet<string> LabelList = new(); // Gmail に転送 (インポート) する際、指定した名前のラベルを付ける。(複数指定可能)
}

public static class LibMailFilterExec
{
    // ★参照アセンブリ一覧は「毎回作ると遅い」ため、最初に一度だけ構築して使い回す
    private static readonly IReadOnlyList<MetadataReference> CachedReferences = BuildReferencesOnce();

    // ★sourceCode ごとに「コンパイル済み呼び出し関数」をキャッシュする
    // - キー：sourceCode の SHA-256（長文でも固定長で高速）
    // - 値：UserFilterClass.UserFilter のデリゲート（高速呼び出し用）
    // - Lazy にすることで並列時も1回だけコンパイル
    private static readonly ConcurrentDictionary<string, Lazy<Func<MailForwardFilterParam, MailForwardFilterResult>>> FilterDelegateCache =
        new(StringComparer.Ordinal);


    // テスト関数
    public static int Test()
    {
        while (true)
        {
            MailForwardFilterParam p = new();
            p.Mail = null!;// ここでメール本文を指定

            // ここにユーザーのフィルタコードが文字列で入る想定
            string src =
@"public static class UserFilterClass
{
    public static MailForwardFilterResult UserFilter(MailForwardFilterParam mail)
    {
        MailForwardFilterResult result = new();

        // ここで mail の内容を検査してフィルタ処理を実施

        result.MarkAsRead = true;

        result.LabelList.Add(""Label1"");
        result.LabelList.Add(""Label2"");

        return result;
    }
}";

            Console.WriteLine("Hello");

            // ★ sourceCode が同じなら2回目以降はコンパイルせず高速呼び出し
            MailForwardFilterResult ret = CompileAndInvokeUserFilter(src, p);

            Console.WriteLine(ret.MarkAsRead);
            Console.WriteLine(string.Join(",", ret.LabelList));

            // デモ用に少し待つ（不要なら削除）
            // System.Threading.Thread.Sleep(1000);
        }

        // return 0; // unreachable
    }

    /// <summary>
    /// sourceCode をキーにコンパイル済みデリゲートをキャッシュし、UserFilter を実行する。
    /// </summary>
    /// <param name="sourceCode">ユーザー提供のC#ソースコード（UserFilterClass を含む）</param>
    /// <param name="param">UserFilter に渡す入力</param>
    /// <returns>UserFilter の戻り値</returns>
    public static MailForwardFilterResult CompileAndInvokeUserFilter(string sourceCode, MailForwardFilterParam param)
    {
        // ★内容が同一かどうかを高速に判定するため、sourceCode のハッシュをキーにする
        string cacheKey = ComputeSha256Hex(sourceCode);

        // Lazy を使い、同じ sourceCode について同時に来てもコンパイル1回に抑える
        Lazy<Func<MailForwardFilterParam, MailForwardFilterResult>> lazyDelegate =
            FilterDelegateCache.GetOrAdd(
                cacheKey,
                _ => new Lazy<Func<MailForwardFilterParam, MailForwardFilterResult>>(
                    () => CompileToFilterDelegate(sourceCode),
                    isThreadSafe: true
                )
            );

        // キャッシュされた（または初回生成された）デリゲートで高速実行
        Func<MailForwardFilterParam, MailForwardFilterResult> filterFunc = lazyDelegate.Value;
        return filterFunc(param);
    }

    /// <summary>
    /// ユーザーコードをメモリ内コンパイルし、UserFilterClass.UserFilter のデリゲートを生成して返す。
    /// ※ここが重いので sourceCode ごとにキャッシュする。
    /// </summary>
    /// <param name="sourceCode">ユーザー提供のC#ソースコード</param>
    /// <returns>UserFilter を呼び出すデリゲート</returns>
    private static Func<MailForwardFilterParam, MailForwardFilterResult> CompileToFilterDelegate(string sourceCode)
    {
        // ★ ユーザーコードは dn_pop3_to_gmail_forwarder を暗黙 using しているものとしてコンパイルする [251223_BBAX3A]
        string sourceCodeWithImplicitUsings = BuildUserSourceWithImplicitUsings(sourceCode);

        // 解析（構文木）
        SyntaxTree syntaxTree = CSharpSyntaxTree.ParseText(
            sourceCodeWithImplicitUsings,
            new CSharpParseOptions(LanguageVersion.CSharp10) // .NET 6 相当（C# 10）
        );

        // コンパイル設定（DLLとして生成、ただし Emit は MemoryStream へ）
        CSharpCompilation compilation = CSharpCompilation.Create(
            assemblyName: "UserDynamicAssembly_" + Guid.NewGuid().ToString("N"),
            syntaxTrees: new[] { syntaxTree },
            references: CachedReferences,
            options: new CSharpCompilationOptions(
                outputKind: OutputKind.DynamicallyLinkedLibrary,
                optimizationLevel: OptimizationLevel.Release,
                allowUnsafe: false
            )
        );

        using MemoryStream peStream = new();

        // ★重要：Emit の出力先を MemoryStream にすることで、dllファイルを一切生成しない
        EmitResult emitResult = compilation.Emit(peStream);

        if (!emitResult.Success)
        {
            string message = string.Join(
                Environment.NewLine,
                emitResult.Diagnostics
                    .Where(d => d.Severity == DiagnosticSeverity.Error)
                    .Select(d => d.ToString())
            );

            throw new InvalidOperationException("ユーザーコードのコンパイルに失敗しました。" + Environment.NewLine + message);
        }

        // 先頭に巻き戻してロード
        peStream.Position = 0;

        // ★キャッシュ前提なので、ロードしたアセンブリは保持する（速度優先）
        // もしメモリを抑えたい場合は isCollectible:true + LRU + Unload を別途設計する
        AssemblyLoadContext loadContext = new(
            name: "UserDynamicContext_" + Guid.NewGuid().ToString("N"),
            isCollectible: false
        );

        Assembly userAssembly = loadContext.LoadFromStream(peStream);

        // UserFilterClass を取得
        Type userFilterClassType = userAssembly.GetType("UserFilterClass", throwOnError: true, ignoreCase: false)!;

        // UserFilter メソッドを取得
        MethodInfo userFilterMethod = userFilterClassType.GetMethod("UserFilter", BindingFlags.Public | BindingFlags.Static)
            ?? throw new MissingMethodException("UserFilterClass.UserFilter が見つかりません。public static MailForwardFilterResult UserFilter(MailForwardFilterParam mail) を定義してください。");

        // シグネチャ検証（安全のため）
        ParameterInfo[] parameters = userFilterMethod.GetParameters();
        if (parameters.Length != 1 || parameters[0].ParameterType != typeof(MailForwardFilterParam))
        {
            throw new InvalidOperationException("UserFilter の引数が一致しません。UserFilter(MailForwardFilterParam mail) にしてください。");
        }

        if (userFilterMethod.ReturnType != typeof(MailForwardFilterResult))
        {
            throw new InvalidOperationException("UserFilter の戻り値が一致しません。MailForwardFilterResult を返してください。");
        }

        // ★反射Invokeは遅いのでデリゲート化（高速化の核心）
        return (Func<MailForwardFilterParam, MailForwardFilterResult>)userFilterMethod.CreateDelegate(
            typeof(Func<MailForwardFilterParam, MailForwardFilterResult>)
        );
    }

    /// <summary>
    /// ユーザーコードに、暗黙 using を付与してコンパイル用ソースコードを生成します。
    /// </summary>
    /// <param name="sourceCode">ユーザー提供のC#ソースコードです。</param>
    /// <returns>暗黙 using を付与したソースコードです。</returns>
    private static string BuildUserSourceWithImplicitUsings(string sourceCode)
    {
        sourceCode ??= "";

        const string ns = "dn_pop3_to_gmail_forwarder";

        if (sourceCode.IndexOf("global using " + ns, StringComparison.Ordinal) >= 0 ||
            sourceCode.IndexOf("using " + ns, StringComparison.Ordinal) >= 0)
        {
            return sourceCode;
        }

        return "using " + ns + ";\n" + sourceCode;
    }

    /// <summary>
    /// コンパイル参照を一度だけ構築する。
    /// - 実行中にロード済みで Location が取れるアセンブリを参照に追加
    /// - ホスト側アセンブリ（MailForwardFilterParam / Result が含まれる）も必ず追加
    /// </summary>
    /// <returns>Roslyn コンパイル用参照一覧</returns>
    private static IReadOnlyList<MetadataReference> BuildReferencesOnce()
    {
        List<MetadataReference> refs = new();

        foreach (Assembly asm in AppDomain.CurrentDomain.GetAssemblies())
        {
            string? location;
            try
            {
                location = asm.Location;
            }
            catch
            {
                continue;
            }

            if (string.IsNullOrWhiteSpace(location))
            {
                continue;
            }

            refs.Add(MetadataReference.CreateFromFile(location));
        }

        // ★ホスト側アセンブリ参照（このファイルで定義した型をユーザーコードが使うため必須）
        refs.Add(MetadataReference.CreateFromFile(typeof(MailForwardFilterParam).Assembly.Location));

        return refs
            .Distinct(MetadataReferenceComparer.Instance)
            .ToList();
    }

    /// <summary>
    /// SHA-256 を16進文字列で返す（キャッシュキー用途）。
    /// </summary>
    /// <param name="text">ハッシュ化対象文字列</param>
    /// <returns>SHA-256 の16進文字列</returns>
    private static string ComputeSha256Hex(string text)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(text);
        byte[] hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash);
    }

    /// <summary>
    /// MetadataReference の重複排除用（FilePath で比較）
    /// </summary>
    private sealed class MetadataReferenceComparer : IEqualityComparer<MetadataReference>
    {
        public static readonly MetadataReferenceComparer Instance = new();

        public bool Equals(MetadataReference? x, MetadataReference? y)
        {
            if (ReferenceEquals(x, y))
            {
                return true;
            }

            if (x is null || y is null)
            {
                return false;
            }

            string? xPath = (x as PortableExecutableReference)?.FilePath;
            string? yPath = (y as PortableExecutableReference)?.FilePath;

            return string.Equals(xPath, yPath, StringComparison.OrdinalIgnoreCase);
        }

        public int GetHashCode(MetadataReference obj)
        {
            string path = (obj as PortableExecutableReference)?.FilePath ?? string.Empty;
            return StringComparer.OrdinalIgnoreCase.GetHashCode(path);
        }
    }
}
