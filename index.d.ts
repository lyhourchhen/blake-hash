export class Blake2BHasher {
  
  constructor()
  update(input: string | Buffer | number): void
  digest(format: string | null): string
  digestBuffer(): Buffer
}
export class Blake2SHasher {
  
  constructor()
  update(input: string | Buffer | number): void
  digest(format: string | null): string
  digestBuffer(): Buffer
}
export class Blake3Hasher {
  
  constructor()
  update(input: string | Buffer | number): void
  digest(format: string | null): string
  digestBuffer(): Buffer
}
