import { Secret, SecretsResolver } from "didcomm-js";

export class ExampleSecretsResolver implements SecretsResolver {
  known_secrets: Secret[];

  constructor(known_secrets: Secret[]) {
    this.known_secrets = known_secrets;
  }

  async get_secret(secret_id: string): Promise<Secret | null> {
    return this.known_secrets.find((secret) => secret.id == secret_id);
  }

  async find_secrets(secret_ids: string[]): Promise<string[]> {
    let secrets = secret_ids.filter((id) =>
      this.known_secrets.find((secret) => secret.id == id)
    );
    return secrets;
  }
}

type MockGet = (secret_id: string) => Secret | null;
type MockFind = (secret_ids: string[]) => string[];

export class MockSecretsResolver implements SecretsResolver {
  get_handlers: MockGet[];
  find_handlers: MockFind[];
  fallback: SecretsResolver;

  constructor(
    get_handlers: MockGet[],
    find_handlers: MockFind[],
    fallback: SecretsResolver
  ) {
    this.get_handlers = get_handlers;
    this.find_handlers = find_handlers;
    this.fallback = fallback;
  }

  async get_secret(secret_id: string): Promise<Secret | null> {
    let handler = this.get_handlers.pop();

    return handler
      ? handler(secret_id)
      : await this.fallback.get_secret(secret_id);
  }

  async find_secrets(secret_ids: string[]): Promise<string[]> {
    let handler = this.find_handlers.pop();

    return handler
      ? handler(secret_ids)
      : await this.fallback.find_secrets(secret_ids);
  }
}
