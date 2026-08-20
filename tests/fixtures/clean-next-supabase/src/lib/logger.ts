type Fields = Record<string, string | number | boolean | null>;

function emit(level: string, message: string, fields: Fields = {}) {
  process.stdout.write(JSON.stringify({ level, message, ...fields }) + "\n");
}

export const logger = {
  info: (message: string, fields?: Fields) => emit("info", message, fields),
  error: (message: string, fields?: Fields) => emit("error", message, fields),
};

export function logRequest(userId: string) {
  logger.info("request", { userId });
}
