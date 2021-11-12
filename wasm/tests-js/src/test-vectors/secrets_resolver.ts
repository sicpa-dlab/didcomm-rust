// TODO: typing mist be in d.ts file for didcomm-js

export type Secret = any;

export interface SecretsResolver {
    get_secret(secret_id: String): Promise<Secret | null>;

    find_secrets(secret_ids: Array<String>): Promise<Array<String>>;
}

export class ExampleSecretsResolver implements SecretsResolver {
    known_secrets: Array<Secret>;

    constructor(known_secrets: Array<Secret>) {
        this.known_secrets = known_secrets;
    }

    async get_secret(secret_id: String): Promise<Secret | null> {
        return this.known_secrets.find((secret) => secret.id == secret_id);
    }

    async find_secrets(secret_ids: Array<String>): Promise<Array<String>> {
        let secrets = secret_ids.filter((id) => this.known_secrets.find((secret) => secret.id == id))
        return secrets;
    }
}