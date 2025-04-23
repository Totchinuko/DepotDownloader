// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

namespace DepotDownloader;

public readonly struct Progress(ulong current, ulong total, ulong publishedId)
{
    public readonly ulong Current = current;
    public readonly ulong Total = total;
    public readonly ulong PublishedId = publishedId;

    public static Progress Empty => new(0L, 0L, 0L);
    public readonly bool IsFile => PublishedId != 0L;
}
