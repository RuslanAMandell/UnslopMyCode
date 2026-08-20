"use client";

export default function Error({ reset }: { error: Error; reset: () => void }) {
  return (
    <div role="alert">
      <p>Something went wrong loading this page.</p>
      <button onClick={() => reset()}>Try again</button>
    </div>
  );
}
