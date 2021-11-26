import { Message } from "didcomm-js";
import {
    MESSAGE_SIMPLE,
  } from "../test-vectors";
  
  test.each([
    {
      case: "Not Forward",
      message: MESSAGE_SIMPLE,
    }
  ])(
    "Message.try-parse-forward handles $case",
    async ({ message }) => {
      const res = message.try_parse_forward();
      expect(res).toBeNull();
    }
  );