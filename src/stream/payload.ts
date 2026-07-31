/**
 * The sample stream: a settlement batch, chosen so that each attack changes what the
 * *application* would do, not merely which bytes it received. A demo that reorders
 * lorem ipsum teaches nothing; a demo that reorders a hold ahead of the payment it is
 * meant to block teaches the whole lesson in one line.
 */

import { utf8 } from './bytes.js'

export interface PayloadLine {
  /** The segment text, exactly as it is encrypted. */
  readonly text: string
  /** Short label for the segment card in the chain visualization. */
  readonly tag: string
  /** Why this line matters if it moves or disappears. */
  readonly consequence: string
}

export const LEDGER: readonly PayloadLine[] = [
  {
    text: 'BATCH 2026-07-31 · Ward & Co · settlement open',
    tag: 'open',
    consequence: 'Opens the batch and fixes its date.',
  },
  {
    text: 'PAY   acct 4471   EUR      12,400.00',
    tag: 'pay 4471',
    consequence: 'A routine payment.',
  },
  {
    text: 'HOLD  acct 8812   fraud review — do not release',
    tag: 'hold 8812',
    consequence: 'The only thing standing between account 8812 and EUR 980,000.',
  },
  {
    text: 'PAY   acct 8812   EUR     980,000.00',
    tag: 'pay 8812',
    consequence: 'Must never execute unless the HOLD above it was read first.',
  },
  {
    text: 'PAY   acct 2039   EUR       3,150.00',
    tag: 'pay 2039',
    consequence: 'A routine payment.',
  },
  {
    text: 'END BATCH · 3 payments · 1 hold · EUR 995,550.00',
    tag: 'end',
    consequence: 'The totals the receiver reconciles against. Losing it hides everything else.',
  },
]

export const LEDGER_SEGMENTS: readonly Uint8Array[] = LEDGER.map((l) => utf8(l.text))

/** What an attacker achieves against a verifier that accepts the mangled batch. */
export const ATTACK_OUTCOMES: Record<string, string> = {
  truncate:
    'The batch now ends mid-list. A receiver that trusts it books 4 lines and never sees the totals it was supposed to reconcile against.',
  reorder:
    'PAY 8812 now arrives before the HOLD that was meant to block it. EUR 980,000 leaves the building, and the hold lands on an account that has already paid.',
  drop: 'The HOLD is simply gone. EUR 980,000 pays out of an account that was under fraud review.',
}
