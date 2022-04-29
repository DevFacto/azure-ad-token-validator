class SimpleCache<T> {
  memoryCache: Record<string, T> = {};

  public getItem(key: string): T | undefined {
    return this.memoryCache.hasOwnProperty(key)
      ? this.memoryCache[key]
      : undefined;
  }

  public setItem(key: string, value: T): void {
    this.memoryCache[key] = value;
  }
}

export default SimpleCache;
