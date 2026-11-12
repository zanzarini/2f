export interface Action {
  type: string;
  /** Plain decimal string, for example "1500.25". Never a number. */
  amount?: string;
  asset?: string;
  destination?: string;
  meta?: Record<string, unknown>;
}

export type ChallengeState = "pending" | "allowed" | "approved" | "denied" | "rejected" | "expired";

export interface Challenge {
  id: string;
  state: ChallengeState;
  action_hash: string;
  rule: string | null;
  requirements: unknown[] | null;
  approvals: { approver: string; kind: string }[];
  expires_at: number;
  approve_url: string | null;
  receipt: string | null;
}

export interface ReceiptPayload {
  v: 1;
  id: string;
  project: string;
  challenge: string;
  action_hash: string;
  decision: "allow" | "approved";
  rule: string;
  approvals: { approver: string; kind: string; strength: "weak" | "strong"; sig: string }[];
  binding_expires_at: number;
  issued_at: number;
  expires_at: number;
  kid: string;
}

export interface Authorization {
  authorized: boolean;
  state: ChallengeState;
  receipt: string | null;
  payload: ReceiptPayload | null;
  challenge: Challenge;
}

export class TwoFError extends Error {
  code: string;
  constructor(code: string, message: string);
}

export function canonical(value: unknown): string;
export function actionHash(action: Action): string;
export function bindingHash(binding: object): Buffer;
export function verifyReceipt(token: string, publicKeys: Record<string, string>, action: Action, now?: number): ReceiptPayload;
export function pinnedApprovers(payload: ReceiptPayload, pinned: Record<string, string>): string[];

export class TwoF {
  constructor(options: { url: string; apiKey: string; publicKeys: Record<string, string>; fetch?: typeof fetch; allowInsecure?: boolean });
  createChallenge(action: Action, idempotencyKey: string): Promise<Challenge>;
  getChallenge(id: string, waitSeconds?: number): Promise<Challenge>;
  authorize(
    action: Action,
    options: { idempotencyKey: string; timeoutSeconds?: number; consume?: boolean; onPending?: (challenge: Challenge) => void | Promise<void> },
  ): Promise<Authorization>;
  consume(receipt: string): Promise<{ consumed: true; receipt: ReceiptPayload }>;
}
