export function sum(...numbers: number[]) {
  return numbers.reduce((acc, cur) => acc + cur, 0);
}
