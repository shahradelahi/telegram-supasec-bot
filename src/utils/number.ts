export function sum(...numbers: number[]) {
  return numbers.reduce((acc, cur) => acc + cur, 0);
}

export function randomInt(min: number, max: number) {
  return Math.floor(Math.random() * (max - min + 1) + min);
}
