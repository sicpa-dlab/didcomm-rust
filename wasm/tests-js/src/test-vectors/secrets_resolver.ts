import { Secret, SecretsResolver } from "didcomm-js";

export class ExampleSecretsResolver implements SecretsResolver {
  known_secrets: Array<Secret>;

  constructor(known_secrets: Array<Secret>) {
    this.known_secrets = known_secrets;
  }

  async get_secret(secret_id: String): Promise<Secret | null> {
    return this.known_secrets.find((secret) => secret.id == secret_id);
  }

  async find_secrets(secret_ids: Array<String>): Promise<Array<String>> {
    let secrets = secret_ids.filter((id) =>
      this.known_secrets.find((secret) => secret.id == id)
    );
    return secrets;
  }
}
