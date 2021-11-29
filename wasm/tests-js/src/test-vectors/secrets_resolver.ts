/* eslint-disable max-classes-per-file */
import { Secret, SecretsResolver } from "didcomm";

export class ExampleSecretsResolver implements SecretsResolver {
  knownSecrets: Secret[];

  constructor(knownSecrets: Secret[]) {
    this.knownSecrets = knownSecrets;
  }

  async get_secret(secretId: string): Promise<Secret | null> {
    const res = this.knownSecrets.find((secret) => secret.id === secretId);
    return res ? res : null;
  }

  async find_secrets(secretIds: string[]): Promise<string[]> {
    return secretIds.filter((id) =>
      this.knownSecrets.find((secret) => secret.id === id)
    );
  }
}

type MockGet = (secretId: string) => Secret | null;
type MockFind = (secretIds: string[]) => string[];

export class MockSecretsResolver implements SecretsResolver {
  getHandlers: MockGet[];
  findHandlers: MockFind[];
  fallback: SecretsResolver;

  constructor(
    getHandlers: MockGet[],
    findHandlers: MockFind[],
    fallback: SecretsResolver
  ) {
    this.getHandlers = getHandlers;
    this.findHandlers = findHandlers;
    this.fallback = fallback;
  }

  async get_secret(secretId: string): Promise<Secret | null> {
    const handler = this.getHandlers.pop();

    return handler
      ? handler(secretId)
      : await this.fallback.get_secret(secretId);
  }

  async find_secrets(secretIds: string[]): Promise<string[]> {
    const handler = this.findHandlers.pop();

    return handler
      ? handler(secretIds)
      : await this.fallback.find_secrets(secretIds);
  }
}
