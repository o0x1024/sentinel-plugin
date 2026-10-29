/** Run an indexed workload without allocating a task or result array. */
export async function runTaskPool(
  count: number,
  concurrency: number,
  execute: (index: number) => Promise<void>,
  shouldStop: () => boolean,
): Promise<void> {
  let nextIndex = 0;
  let failed = false;
  let failure: unknown;

  const worker = async (): Promise<void> => {
    try {
      while (nextIndex < count && !failed && !shouldStop()) {
        const index = nextIndex++;
        await execute(index);
      }
    } catch (error) {
      if (!failed) {
        failed = true;
        failure = error;
      }
    }
  };

  // Drain the started workers before returning an error. No worker can claim
  // another task after the first failure, including a rejected result commit.
  await Promise.all(Array.from({ length: Math.min(concurrency, count) }, worker));
  if (failed) throw failure;
}
