export function logRequest(userId: string, token: string, password: string) {
  console.log("request from", userId);
  console.log("auth token", token);
  console.debug("password", password);
  console.log("done");
}
