import { Message } from "didcomm-js";
import {
    MESSAGE_SIMPLE,
  } from "../test-vectors";
  
  test.each([
    {
      case: "Simple",
      message: MESSAGE_SIMPLE,
    }
  ])(
    "Message.try-parse-forward handles $case",
    async ({ message }) => {
      const res = Message.try_parse_forward(message);
      //expect(typeof res).toStrictEqual("string");
      //expect(res).toContain("ciphertext");
    }
  );