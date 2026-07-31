/** Typed element lookups that fail loudly instead of silently doing nothing. */

export function el<T extends HTMLElement = HTMLElement>(id: string): T {
  const node = document.getElementById(id)
  if (!node) throw new Error(`missing element #${id}`)
  return node as T
}

export function setText(id: string, text: string): void {
  el(id).textContent = text
}

/** Toggle a class without the `classList.toggle(x, cond)` argument-order trap. */
export function setClass(node: HTMLElement, name: string, on: boolean): void {
  if (on) node.classList.add(name)
  else node.classList.remove(name)
}

export function prefersReducedMotion(): boolean {
  return globalThis.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false
}
