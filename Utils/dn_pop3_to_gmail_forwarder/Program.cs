using System;
using System.Collections.Generic;

internal class Program
{
    private enum Hand
    {
        Rock = 0,
        Scissors = 1,
        Paper = 2
    }

    private static readonly Random Random = new();

    static void Main(string[] args)
    {
        Console.WriteLine("おこしやす。じゃんけんの宿『グー・チョキ・パー』どす。ごゆっくりしていっておくれやす！");
        Console.WriteLine("0: グー, 1: チョキ, 2: パー でございます。");
        Console.WriteLine("お好きなだけ遊んでおくれやす。おいとまの際は \"Q\" とお書きくださいな。");
        Console.WriteLine();

        while (true)
        {
            var playerHand = ReadPlayerHandOrQuit();
            if (playerHand == null)
            {
                Console.WriteLine("本日はお付き合いありがとさんどした。またお越しやす。");
                break;
            }

            var computerHand = GetComputerHand();

            Console.WriteLine($"あなた: {HandLabel(playerHand.Value)}");
            Console.WriteLine($"お宿: {HandLabel(computerHand)}");
            RenderDuel(playerHand.Value, computerHand);

            var result = Judge(playerHand.Value, computerHand);
            Console.WriteLine(ResultMessage(result));

            Console.WriteLine();
            Console.WriteLine("— 次の手を思いつかはったら、いつでもどうぞ。おいとまは \"Q\" と書いておくれやす。");
            Console.WriteLine();
        }
    }

    private static Hand? ReadPlayerHandOrQuit()
    {
        while (true)
        {
            Console.Write("お手をどうぞ (0: グー, 1: チョキ, 2: パー, Q: おいとま): ");
            var input = Console.ReadLine();

            if (string.IsNullOrWhiteSpace(input))
            {
                continue;
            }

            if (input.Trim().Equals("q", StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            if (int.TryParse(input, out var value) &&
                Enum.IsDefined(typeof(Hand), value))
            {
                return (Hand)value;
            }

            Console.WriteLine("0, 1, 2 か Q をお選びくださいな。");
        }
    }

    private static Hand GetComputerHand()
    {
        var value = Random.Next(0, 3);
        return (Hand)value;
    }

    private static string HandLabel(Hand hand)
    {
        return hand switch
        {
            Hand.Rock => "グー",
            Hand.Scissors => "チョキ",
            Hand.Paper => "パー",
            _ => hand.ToString()
        };
    }

    private static void RenderDuel(Hand player, Hand computer)
    {
        var playerArt = HandArt(player, true);
        var houseArt = HandArt(computer, false);
        var height = Math.Max(playerArt.Length, houseArt.Length);

        Console.WriteLine("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓");
        Console.WriteLine("┃　お座敷での手合わせ、ようこそ　┃");
        Console.WriteLine("┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫");
        for (var i = 0; i < height; i++)
        {
            var left = i < playerArt.Length ? playerArt[i] : string.Empty;
            var right = i < houseArt.Length ? houseArt[i] : string.Empty;
            Console.WriteLine($"┃ {PadToWidth(left, 24)} お宿 {PadToWidth(right, 24)}┃");
        }
        Console.WriteLine("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛");
    }

    private static int Judge(Hand player, Hand computer)
    {
        // 0 = draw, 1 = lose, 2 = win
        return ((int)player - (int)computer + 3) % 3;
    }

    private static string ResultMessage(int resultCode)
    {
        return resultCode switch
        {
            0 => "引き分けどすな。",
            1 => "申し訳おへん、お宿の勝ちでおす。",
            2 => "ようお勝ちなはりましたな！",
            _ => "判じかねますわ。"
        };
    }

    private static string PadToWidth(string text, int width)
    {
        if (text.Length >= width)
        {
            return text;
        }

        return text + new string(' ', width - text.Length);
    }

    private static string[] HandArt(Hand hand, bool isPlayer)
    {
        var accent = Accent(isPlayer);
        var indent = Random.Next(0, 3);
        var variants = hand switch
        {
            Hand.Rock => RockVariants(),
            Hand.Scissors => ScissorVariants(),
            Hand.Paper => PaperVariants(),
            _ => RockVariants()
        };

        var chosen = variants[Random.Next(variants.Count)];
        var lines = new string[chosen.Length];
        for (var i = 0; i < chosen.Length; i++)
        {
            var line = chosen[i].Replace("{acc}", accent);
            lines[i] = new string(' ', indent) + line;
        }
        return lines;
    }

    private static List<string[]> RockVariants()
    {
        return new List<string[]>
        {
            new[]
            {
                "   ___{acc}",
                "  / __) ",
                " | (__  ",
                " |___)  ",
                "  /  \\ ",
                " (____)",
                "  |_|  "
            },
            new[]
            {
                "   {acc}___",
                "  ( ___)",
                "  / ___)",
                " ( (___ ",
                "  \\___ )",
                "  (___/ ",
                "   |_|  "
            }
        };
    }

    private static List<string[]> ScissorVariants()
    {
        return new List<string[]>
        {
            new[]
            {
                "   {acc}  /\\",
                "      /  \\",
                "   __/\\__/__",
                "     /  \\",
                "    /____\\",
                "      ||",
                "      VV"
            },
            new[]
            {
                "    {acc}  /\\",
                "   _/  \\",
                "  (  () )",
                "   \\    /",
                "    \\  /",
                "     \\\\",
                "     VV"
            }
        };
    }

    private static List<string[]> PaperVariants()
    {
        return new List<string[]>
        {
            new[]
            {
                " {acc}┌───┬─┐",
                " │ 手 │ ││",
                " │    │ ││",
                " │    │ ││",
                " │    │ ││",
                " └───┴─┘ ",
                "    ||    "
            },
            new[]
            {
                " {acc}┌────┐",
                " │ ひら │",
                " │      │",
                " │      │",
                " │      │",
                " └────┘",
                "    ||   "
            }
        };
    }

    private static string Accent(bool isPlayer)
    {
        var options = isPlayer
            ? new[] { "◇", "☆", "✿", "＊" }
            : new[] { "◆", "★", "◎", "＋" };
        return options[Random.Next(options.Length)];
    }
}
